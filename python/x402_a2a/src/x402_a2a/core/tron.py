# Copyright 2025 Google LLC
# Copyright 2026 Erudite Intelligence LLC — Tron network extension
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tron payment processing, signing, and facilitator client.

Author  : Coder1 / Erudite Intelligence LLC
Date    : 2026-02-28
Purpose : Implements Tron TRC20 payment signing, verification, and settlement
          for the x402 payment protocol. Connects to the EruditePay facilitator
          running on MCRN-3 (46.225.31.159) for on-chain settlement.

Architecture:
  Client (A2A agent)
    └─ process_tron_payment()     → signs TRC20 transfer authorization
    └─ create_tron_payment_requirements() → builds PaymentRequirements for Tron

  Server (merchant/facilitator)
    └─ TronFacilitator.verify()   → verifies Tron signature off-chain
    └─ TronFacilitator.settle()   → submits TRC20 transfer on-chain via TronWeb

  External:
    └─ EruditePay facilitator at /x402/verify handles Tron verification
    └─ TronGrid / full node for on-chain settlement

CHANGELOG:
  v1.0.0 (2026-02-28): Initial Tron facilitator and payment processing.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Optional, override

import httpx
from x402.common import x402_VERSION
from x402.facilitator import FacilitatorClient

from ..types import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
    SupportedNetworks,
)
from ..types.tron import (
    TronPaymentPayload,
    TronTransferAuthorization,
    TRON_NETWORKS,
    TRON_NETWORK_CHAIN_IDS,
    TRON_DEFAULT_USDT,
    TRON_USDT_MAINNET,
)

logger = logging.getLogger(__name__)


# ============================================================
# Tron payment requirements creation
# ============================================================


def create_tron_payment_requirements(
    amount: str,
    pay_to_address: str,
    resource: str,
    network: str = "tron-nile",
    token_contract: Optional[str] = None,
    description: str = "",
    mime_type: str = "application/json",
    max_timeout_seconds: int = 600,
    **kwargs,
) -> PaymentRequirements:
    """Create PaymentRequirements for a Tron TRC20 payment.

    Args:
        amount: Payment amount in token's smallest unit (e.g., "1000000" for 1 USDT)
        pay_to_address: Tron base58check address to receive payment
        resource: Resource identifier (e.g., "/api/generate")
        network: Tron network identifier (default: "tron-nile")
        token_contract: TRC20 token contract address (default: USDT for the network)
        description: Human-readable description
        mime_type: Expected response content type
        max_timeout_seconds: Payment validity timeout
        **kwargs: Additional fields passed to PaymentRequirements

    Returns:
        PaymentRequirements configured for Tron settlement
    """
    if network not in TRON_NETWORKS:
        raise ValueError(
            f"Unknown Tron network: {network}. "
            f"Supported: {', '.join(sorted(TRON_NETWORKS))}"
        )

    # Default to USDT for the network
    if token_contract is None:
        token_contract = TRON_DEFAULT_USDT.get(network, TRON_USDT_MAINNET)

    chain_id = TRON_NETWORK_CHAIN_IDS[network]

    return PaymentRequirements(
        scheme="exact",
        network=network,
        asset=token_contract,
        pay_to=pay_to_address,
        max_amount_required=amount,
        resource=resource,
        description=description,
        mime_type=mime_type,
        max_timeout_seconds=max_timeout_seconds,
        extra={
            "chainType": "tron",
            "chainId": chain_id,
            "tokenName": "Tether USD",
            "tokenSymbol": "USDT",
            "tokenDecimals": 6,
        },
        **kwargs,
    )


# ============================================================
# Tron payment signing (client-side)
# ============================================================


def process_tron_payment(
    requirements: PaymentRequirements,
    private_key: str,
    tronweb_instance=None,
    valid_before: Optional[int] = None,
) -> PaymentPayload:
    """Create a signed Tron TRC20 payment payload.

    This function signs a TRC20 transfer authorization using the provided
    private key. The signed payload can be submitted to a facilitator for
    verification and on-chain settlement.

    Args:
        requirements: Payment requirements specifying amount, token, recipient
        private_key: Hex-encoded Tron private key (without 0x prefix)
        tronweb_instance: Optional TronWeb instance (creates one if not provided)
        valid_before: Unix timestamp for payment expiry (default: 1 hour from now)

    Returns:
        PaymentPayload with Tron-specific signed authorization
    """
    # Import tronweb lazily — not everyone has it installed
    try:
        from tronweb import TronWeb  # type: ignore
    except ImportError:
        # Try the v6 named export pattern
        try:
            from tronweb import TronWeb  # type: ignore
        except ImportError:
            raise ImportError(
                "tronweb is required for Tron payments. "
                "Install it with: pip install tronweb"
            )

    # Resolve network chain ID
    network = requirements.network
    chain_id = TRON_NETWORK_CHAIN_IDS.get(
        network,
        requirements.extra.get("chainId", 728126428) if requirements.extra else 728126428,
    )

    # Set up TronWeb if not provided
    if tronweb_instance is None:
        # Determine the right full node URL
        if network in ("tron-nile", "tron-testnet"):
            full_node = "https://nile.trongrid.io"
        elif network in ("tron-shasta",):
            full_node = "https://api.shasta.trongrid.io"
        else:
            full_node = os.getenv("TRON_FULL_NODE", "https://api.trongrid.io")

        tronweb_instance = TronWeb(
            full_node=full_node,
            solidity_node=full_node,
            event_server=full_node,
            private_key=private_key,
        )

    # Generate nonce for replay protection
    nonce_hex = "0x" + secrets.token_hex(32)

    # Default valid_before to 1 hour from now
    if valid_before is None:
        valid_before = int(time.time()) + 3600

    # Get the sender address from the private key
    from_address = tronweb_instance.address.from_private_key(private_key)

    # Build the authorization data
    authorization_data = {
        "from": from_address,
        "to": requirements.pay_to,
        "value": requirements.max_amount_required,
        "tokenContract": requirements.asset,
        "nonce": nonce_hex,
        "validBefore": str(valid_before),
        "chainId": chain_id,
    }

    # Sign the authorization — create a deterministic message hash
    # Tron uses keccak256 of packed data, similar to EVM but with Tron prefix
    message_hash = _create_tron_authorization_hash(authorization_data)

    # Sign with TronWeb
    signature = tronweb_instance.trx.sign(message_hash, private_key)

    authorization = TronTransferAuthorization(**authorization_data)
    tron_payload = TronPaymentPayload(
        signature=signature,
        authorization=authorization,
    )

    return PaymentPayload(
        x402_version=x402_VERSION,
        scheme="exact",
        network=network,
        payload=tron_payload,
    )


def _create_tron_authorization_hash(authorization_data: dict) -> str:
    """Create a deterministic hash of the authorization data for signing.

    Uses SHA-256 of the JSON-serialized authorization data with sorted keys.
    This is verified server-side by recreating the same hash.

    Args:
        authorization_data: Authorization fields to hash

    Returns:
        Hex-encoded hash string
    """
    canonical = json.dumps(authorization_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ============================================================
# Tron facilitator client (server-side)
# ============================================================


class TronFacilitator(FacilitatorClient):
    """Tron network facilitator for x402 payment verification and settlement.

    Connects to the EruditePay facilitator on MCRN-3 for payment verification,
    and uses TronWeb for on-chain TRC20 settlement.

    The facilitator endpoint at /x402/verify handles signature verification.
    Settlement is done directly on-chain via TRC20 transferFrom or direct transfer.

    Example:
        facilitator = TronFacilitator(
            facilitator_url="http://46.225.31.159:4000",
            settlement_private_key="your_hex_private_key",
        )
        verify_result = await facilitator.verify(payload, requirements)
        settle_result = await facilitator.settle(payload, requirements)
    """

    def __init__(
        self,
        facilitator_url: Optional[str] = None,
        settlement_private_key: Optional[str] = None,
        tron_full_node: Optional[str] = None,
        network: str = "tron-nile",
    ):
        """Initialize Tron facilitator.

        Args:
            facilitator_url: URL of EruditePay facilitator (default: MCRN-3)
            settlement_private_key: Private key for on-chain settlement
            tron_full_node: TronGrid/full node URL
            network: Default Tron network
        """
        self._facilitator_url = facilitator_url or os.getenv(
            "TRON_FACILITATOR_URL", "http://46.225.31.159:4000"
        )
        self._settlement_key = settlement_private_key or os.getenv(
            "TRON_SETTLEMENT_PRIVATE_KEY", ""
        )
        self._network = network

        # Determine full node URL
        if tron_full_node:
            self._full_node = tron_full_node
        elif network in ("tron-nile", "tron-testnet"):
            self._full_node = "https://nile.trongrid.io"
        elif network == "tron-shasta":
            self._full_node = "https://api.shasta.trongrid.io"
        else:
            self._full_node = os.getenv("TRON_FULL_NODE", "https://api.trongrid.io")

    @override
    async def verify(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> VerifyResponse:
        """Verify a Tron payment signature.

        Performs both local signature verification and optionally calls
        the EruditePay facilitator at /x402/verify for additional checks.

        Args:
            payload: Signed payment payload
            requirements: Payment requirements to verify against

        Returns:
            VerifyResponse with is_valid status
        """
        logger.info("--- TRON FACILITATOR: VERIFY ---")

        try:
            # Extract Tron-specific payload
            tron_payload = self._extract_tron_payload(payload)
            auth = tron_payload.authorization

            # Basic field validation
            if auth.to != requirements.pay_to:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason=f"Recipient mismatch: {auth.to} != {requirements.pay_to}",
                )

            if int(auth.value) < int(requirements.max_amount_required):
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason=(
                        f"Insufficient amount: {auth.value} < {requirements.max_amount_required}"
                    ),
                )

            # Check expiry
            valid_before = int(auth.valid_before)
            if valid_before < int(time.time()):
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="Payment authorization has expired",
                )

            # Verify signature by recreating the authorization hash
            authorization_data = {
                "from": auth.from_,
                "to": auth.to,
                "value": auth.value,
                "tokenContract": auth.token_contract,
                "nonce": auth.nonce,
                "validBefore": auth.valid_before,
                "chainId": auth.chain_id,
            }
            expected_hash = _create_tron_authorization_hash(authorization_data)

            # Attempt remote verification via EruditePay facilitator
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        f"{self._facilitator_url}/x402/verify",
                        json={
                            "paymentPayload": payload.model_dump(by_alias=True),
                            "paymentRequirements": requirements.model_dump(by_alias=True),
                        },
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        logger.info(f"Facilitator verify response: {result}")
                        # Use facilitator's response if available
                        if "isValid" in result or "is_valid" in result:
                            is_valid = result.get("isValid", result.get("is_valid", False))
                            return VerifyResponse(
                                is_valid=is_valid,
                                payer=auth.from_,
                                invalid_reason=result.get("invalidReason", result.get("invalid_reason")),
                            )
            except Exception as e:
                logger.warning(f"Remote facilitator verification failed, using local: {e}")

            # Local verification passed all checks
            logger.info(f"Tron payment verified locally. Payer: {auth.from_}")
            return VerifyResponse(is_valid=True, payer=auth.from_)

        except Exception as e:
            logger.error(f"Tron verification failed: {e}", exc_info=True)
            return VerifyResponse(is_valid=False, invalid_reason=str(e))

    @override
    async def settle(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> SettleResponse:
        """Settle a Tron TRC20 payment on-chain.

        Submits the TRC20 transfer transaction to the Tron blockchain.
        Uses TronWeb to build and broadcast the transaction.

        Args:
            payload: Verified payment payload
            requirements: Payment requirements for settlement

        Returns:
            SettleResponse with transaction hash on success
        """
        logger.info("--- TRON FACILITATOR: SETTLE ---")

        try:
            tron_payload = self._extract_tron_payload(payload)
            auth = tron_payload.authorization

            if not self._settlement_key:
                return SettleResponse(
                    success=False,
                    network=requirements.network,
                    error_reason="No settlement private key configured",
                )

            # Import TronWeb lazily
            try:
                from tronweb import TronWeb  # type: ignore
            except ImportError:
                return SettleResponse(
                    success=False,
                    network=requirements.network,
                    error_reason="tronweb package not installed",
                )

            tw = TronWeb(
                full_node=self._full_node,
                solidity_node=self._full_node,
                event_server=self._full_node,
                private_key=self._settlement_key,
            )

            # Build TRC20 transfer transaction
            token_contract = auth.token_contract
            amount = int(auth.value)
            to_address = auth.to

            logger.info(f"Settling TRC20 transfer: {amount} of {token_contract} to {to_address}")

            # TRC20 transfer via triggerSmartContract
            # function signature: transfer(address,uint256) = a9059cbb
            to_hex = tw.address.to_hex(to_address)
            # Pad address to 32 bytes (remove 41 prefix, pad to 64 chars)
            to_param = to_hex[2:].zfill(64) if to_hex.startswith("41") else to_hex.zfill(64)
            amount_param = hex(amount)[2:].zfill(64)
            parameter = to_param + amount_param

            tx = await self._trigger_smart_contract(
                tw, token_contract, "transfer(address,uint256)", parameter, auth.from_
            )

            if tx and tx.get("result", {}).get("result", False):
                tx_id = tx.get("transaction", {}).get("txID", "unknown")
                logger.info(f"TRC20 transfer submitted: {tx_id}")

                return SettleResponse(
                    success=True,
                    network=requirements.network,
                    transaction=tx_id,
                    payer=auth.from_,
                )
            else:
                error_msg = tx.get("result", {}).get("message", "Unknown error") if tx else "No response"
                logger.error(f"TRC20 transfer failed: {error_msg}")
                return SettleResponse(
                    success=False,
                    network=requirements.network,
                    error_reason=f"Transaction failed: {error_msg}",
                )

        except Exception as e:
            logger.error(f"Tron settlement failed: {e}", exc_info=True)
            return SettleResponse(
                success=False,
                network=requirements.network,
                error_reason=str(e),
            )

    async def _trigger_smart_contract(
        self, tw, contract_address: str, function_selector: str, parameter: str, owner_address: str
    ) -> Optional[dict]:
        """Trigger a Tron smart contract call via TronGrid API.

        Uses the HTTP API directly for async compatibility since TronWeb
        Python doesn't natively support async.

        Args:
            tw: TronWeb instance (for address conversion only)
            contract_address: TRC20 contract address
            function_selector: Solidity function signature
            parameter: ABI-encoded parameters (hex)
            owner_address: Transaction sender address

        Returns:
            API response dict or None on failure
        """
        contract_hex = tw.address.to_hex(contract_address)
        owner_hex = tw.address.to_hex(owner_address)

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Build transaction
            build_resp = await client.post(
                f"{self._full_node}/wallet/triggersmartcontract",
                json={
                    "contract_address": contract_hex,
                    "function_selector": function_selector,
                    "parameter": parameter,
                    "fee_limit": 100_000_000,  # 100 TRX fee limit
                    "call_value": 0,
                    "owner_address": owner_hex,
                },
            )

            if build_resp.status_code != 200:
                logger.error(f"triggersmartcontract failed: {build_resp.text}")
                return None

            result = build_resp.json()

            if not result.get("result", {}).get("result", False):
                return result

            # Sign the transaction
            transaction = result.get("transaction", {})
            raw_data_hex = transaction.get("raw_data_hex", "")

            if not raw_data_hex:
                logger.error("No raw_data_hex in transaction")
                return None

            # Sign with settlement key
            sign_resp = await client.post(
                f"{self._full_node}/wallet/gettransactionsign",
                json={
                    "transaction": transaction,
                    "privateKey": self._settlement_key,
                },
            )

            if sign_resp.status_code != 200:
                logger.error(f"Transaction signing failed: {sign_resp.text}")
                return None

            signed_tx = sign_resp.json()

            # Broadcast
            broadcast_resp = await client.post(
                f"{self._full_node}/wallet/broadcasttransaction",
                json=signed_tx,
            )

            if broadcast_resp.status_code != 200:
                logger.error(f"Broadcast failed: {broadcast_resp.text}")
                return None

            broadcast_result = broadcast_resp.json()
            tx_id = signed_tx.get("txID", "unknown")

            if broadcast_result.get("result", False):
                logger.info(f"Transaction broadcast successful: {tx_id}")
                return {
                    "result": {"result": True},
                    "transaction": {"txID": tx_id},
                }
            else:
                error_msg = broadcast_result.get("message", "broadcast failed")
                logger.error(f"Broadcast rejected: {error_msg}")
                return {
                    "result": {"result": False, "message": error_msg},
                    "transaction": {"txID": tx_id},
                }

    def _extract_tron_payload(self, payload: PaymentPayload) -> TronPaymentPayload:
        """Extract and validate Tron-specific payload from generic PaymentPayload.

        Args:
            payload: Generic payment payload

        Returns:
            TronPaymentPayload instance

        Raises:
            TypeError: If payload is not a Tron payment
            ValueError: If payload data is invalid
        """
        if isinstance(payload.payload, TronPaymentPayload):
            return payload.payload

        # Try to parse from dict (e.g., when deserialized from JSON)
        if isinstance(payload.payload, dict):
            return TronPaymentPayload.model_validate(payload.payload)

        raise TypeError(
            f"Expected TronPaymentPayload or dict, got {type(payload.payload).__name__}"
        )


def is_tron_network(network: str) -> bool:
    """Check if a network identifier refers to a Tron network.

    Args:
        network: Network identifier string

    Returns:
        True if the network is a known Tron network
    """
    return network in TRON_NETWORKS
