# Copyright 2026 Erudite Intelligence LLC
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
"""Unit tests for Tron network support in x402 A2A extension.

Author  : Coder1 / Erudite Intelligence LLC
Date    : 2026-02-28
Purpose : Verify Tron types, payment requirements creation, facilitator
          verification logic, and network detection.

CHANGELOG:
  v1.0.0 (2026-02-28): Initial Tron unit tests.
"""

import time

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from x402_a2a.types.tron import (
    TronPaymentPayload,
    TronTransferAuthorization,
    TRON_NETWORKS,
    TRON_NETWORK_CHAIN_IDS,
    TRON_DEFAULT_USDT,
    TRON_USDT_MAINNET,
    TRON_USDT_NILE,
    TRON_USDT_SHASTA,
    TRON_MAINNET_CHAIN_ID,
    TRON_NILE_CHAIN_ID,
    TRON_SHASTA_CHAIN_ID,
)
from x402_a2a.core.tron import (
    TronFacilitator,
    create_tron_payment_requirements,
    is_tron_network,
    _create_tron_authorization_hash,
)
from x402_a2a.core.merchant import create_payment_requirements
from x402_a2a.types import (
    PaymentPayload,
    PaymentRequirements,
    VerifyResponse,
    SettleResponse,
)


# ============================================================
# Tron type tests
# ============================================================


class TestTronTypes:
    """Tests for Tron-specific Pydantic models."""

    def test_tron_transfer_authorization_creation(self):
        """TronTransferAuthorization can be created with valid fields."""
        auth = TronTransferAuthorization(
            **{
                "from": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
                "to": "TLPxBbm25LzJoUUwNj45BFnthDMRECiDjW",
                "value": "1000000",
                "tokenContract": TRON_USDT_NILE,
                "nonce": "0xabcdef1234567890",
                "validBefore": str(int(time.time()) + 3600),
                "chainId": TRON_NILE_CHAIN_ID,
            }
        )
        assert auth.from_ == "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
        assert auth.to == "TLPxBbm25LzJoUUwNj45BFnthDMRECiDjW"
        assert auth.value == "1000000"
        assert auth.token_contract == TRON_USDT_NILE
        assert auth.chain_id == TRON_NILE_CHAIN_ID

    def test_tron_payment_payload_creation(self):
        """TronPaymentPayload can be created with authorization and signature."""
        auth = TronTransferAuthorization(
            **{
                "from": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
                "to": "TLPxBbm25LzJoUUwNj45BFnthDMRECiDjW",
                "value": "5000000",
                "tokenContract": TRON_USDT_MAINNET,
                "nonce": "0x1234",
                "validBefore": "9999999999",
                "chainId": TRON_MAINNET_CHAIN_ID,
            }
        )
        payload = TronPaymentPayload(
            signature="0xdeadbeef",
            authorization=auth,
        )
        assert payload.signature == "0xdeadbeef"
        assert payload.authorization.value == "5000000"
        assert payload.raw_transaction is None

    def test_tron_payload_serialization(self):
        """TronPaymentPayload serializes to dict correctly with aliases."""
        auth = TronTransferAuthorization(
            **{
                "from": "TSenderAddress",
                "to": "TReceiverAddress",
                "value": "100",
                "tokenContract": TRON_USDT_NILE,
                "nonce": "0xabc",
                "validBefore": "1000",
                "chainId": TRON_NILE_CHAIN_ID,
            }
        )
        payload = TronPaymentPayload(signature="0xsig", authorization=auth)
        data = payload.model_dump(by_alias=True)

        assert data["authorization"]["from"] == "TSenderAddress"
        assert data["authorization"]["tokenContract"] == TRON_USDT_NILE
        assert data["authorization"]["chainId"] == TRON_NILE_CHAIN_ID

    def test_tron_payload_from_dict(self):
        """TronPaymentPayload can be deserialized from a dict."""
        data = {
            "signature": "0xsig123",
            "authorization": {
                "from": "TSender",
                "to": "TReceiver",
                "value": "200",
                "tokenContract": TRON_USDT_MAINNET,
                "nonce": "0xnonce",
                "validBefore": "2000",
                "chainId": TRON_MAINNET_CHAIN_ID,
            },
        }
        payload = TronPaymentPayload.model_validate(data)
        assert payload.signature == "0xsig123"
        assert payload.authorization.from_ == "TSender"
        assert payload.authorization.chain_id == TRON_MAINNET_CHAIN_ID


# ============================================================
# Network constants tests
# ============================================================


class TestTronConstants:
    """Tests for Tron network constants."""

    def test_tron_networks_set(self):
        """All expected Tron network identifiers are present."""
        assert "tron" in TRON_NETWORKS
        assert "tron-mainnet" in TRON_NETWORKS
        assert "tron-nile" in TRON_NETWORKS
        assert "tron-testnet" in TRON_NETWORKS
        assert "tron-shasta" in TRON_NETWORKS
        assert "base" not in TRON_NETWORKS
        assert "ethereum" not in TRON_NETWORKS

    def test_chain_ids(self):
        """Chain IDs are correct for each network."""
        assert TRON_MAINNET_CHAIN_ID == 728126428
        assert TRON_NILE_CHAIN_ID == 3448148188
        assert TRON_SHASTA_CHAIN_ID == 2494104990

    def test_default_usdt_addresses(self):
        """Default USDT addresses are set for each network."""
        assert TRON_DEFAULT_USDT["tron"] == TRON_USDT_MAINNET
        assert TRON_DEFAULT_USDT["tron-nile"] == TRON_USDT_NILE
        assert TRON_DEFAULT_USDT["tron-shasta"] == TRON_USDT_SHASTA

    def test_is_tron_network(self):
        """is_tron_network correctly identifies Tron networks."""
        assert is_tron_network("tron") is True
        assert is_tron_network("tron-nile") is True
        assert is_tron_network("tron-mainnet") is True
        assert is_tron_network("tron-testnet") is True
        assert is_tron_network("tron-shasta") is True
        assert is_tron_network("base") is False
        assert is_tron_network("base-sepolia") is False
        assert is_tron_network("ethereum") is False
        assert is_tron_network("") is False


# ============================================================
# Payment requirements creation tests
# ============================================================


class TestTronPaymentRequirements:
    """Tests for Tron payment requirements creation."""

    def test_create_tron_requirements_basic(self):
        """create_tron_payment_requirements creates valid requirements."""
        req = create_tron_payment_requirements(
            amount="1000000",
            pay_to_address="TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
            resource="/api/service",
            network="tron-nile",
        )
        assert req.network == "tron-nile"
        assert req.asset == TRON_USDT_NILE
        assert req.max_amount_required == "1000000"
        assert req.pay_to == "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
        assert req.scheme == "exact"
        assert req.extra["chainType"] == "tron"
        assert req.extra["chainId"] == TRON_NILE_CHAIN_ID

    def test_create_tron_requirements_mainnet(self):
        """create_tron_payment_requirements works for mainnet."""
        req = create_tron_payment_requirements(
            amount="5000000",
            pay_to_address="TMainnetAddr",
            resource="/paid",
            network="tron",
        )
        assert req.network == "tron"
        assert req.asset == TRON_USDT_MAINNET
        assert req.extra["chainId"] == TRON_MAINNET_CHAIN_ID

    def test_create_tron_requirements_custom_token(self):
        """Custom token contract can be specified."""
        custom_token = "TCustomTokenContractAddr"
        req = create_tron_payment_requirements(
            amount="100",
            pay_to_address="TAddr",
            resource="/x",
            network="tron-nile",
            token_contract=custom_token,
        )
        assert req.asset == custom_token

    def test_create_tron_requirements_invalid_network(self):
        """Invalid Tron network raises ValueError."""
        with pytest.raises(ValueError, match="Unknown Tron network"):
            create_tron_payment_requirements(
                amount="100",
                pay_to_address="TAddr",
                resource="/x",
                network="base",
            )

    def test_create_payment_requirements_routes_tron(self):
        """create_payment_requirements (unified) routes Tron networks correctly."""
        req = create_payment_requirements(
            price="$1.00",
            pay_to_address="TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
            resource="/test",
            network="tron-nile",
        )
        assert req.network == "tron-nile"
        assert req.asset == TRON_USDT_NILE
        assert req.extra["chainType"] == "tron"
        # $1.00 = 1000000 atomic units (6 decimals)
        assert req.max_amount_required == "1000000"

    def test_create_payment_requirements_tron_dollar_amount(self):
        """Dollar amounts are correctly converted for Tron."""
        req = create_payment_requirements(
            price="$0.50",
            pay_to_address="TAddr",
            resource="/x",
            network="tron-nile",
        )
        assert req.max_amount_required == "500000"

    def test_create_payment_requirements_tron_raw_amount(self):
        """Raw atomic amounts pass through correctly for Tron."""
        req = create_payment_requirements(
            price="2500000",
            pay_to_address="TAddr",
            resource="/x",
            network="tron-nile",
        )
        assert req.max_amount_required == "2500000"

    def test_create_payment_requirements_tron_numeric(self):
        """Numeric prices are treated as USD for Tron."""
        req = create_payment_requirements(
            price=3.50,
            pay_to_address="TAddr",
            resource="/x",
            network="tron",
        )
        assert req.max_amount_required == "3500000"


# ============================================================
# Authorization hash tests
# ============================================================


class TestAuthorizationHash:
    """Tests for the deterministic authorization hash."""

    def test_hash_deterministic(self):
        """Same input produces same hash."""
        data = {
            "from": "TSender",
            "to": "TReceiver",
            "value": "100",
            "tokenContract": TRON_USDT_NILE,
            "nonce": "0xabc",
            "validBefore": "1000",
            "chainId": TRON_NILE_CHAIN_ID,
        }
        h1 = _create_tron_authorization_hash(data)
        h2 = _create_tron_authorization_hash(data)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_hash_changes_with_input(self):
        """Different inputs produce different hashes."""
        data1 = {"from": "A", "to": "B", "value": "100"}
        data2 = {"from": "A", "to": "B", "value": "200"}
        assert _create_tron_authorization_hash(data1) != _create_tron_authorization_hash(data2)


# ============================================================
# TronFacilitator verification tests
# ============================================================


class TestTronFacilitatorVerify:
    """Tests for TronFacilitator.verify() method."""

    @pytest.fixture
    def facilitator(self):
        """Create a TronFacilitator for testing."""
        return TronFacilitator(
            facilitator_url="http://localhost:9999",
            settlement_private_key="test_key",
            network="tron-nile",
        )

    @pytest.fixture
    def sample_tron_requirements(self):
        """Sample Tron payment requirements."""
        return PaymentRequirements(
            scheme="exact",
            network="tron-nile",
            asset=TRON_USDT_NILE,
            pay_to="TReceiverAddress",
            max_amount_required="1000000",
            resource="/test",
            description="Test",
            mime_type="application/json",
            max_timeout_seconds=600,
            extra={"chainType": "tron", "chainId": TRON_NILE_CHAIN_ID},
        )

    def _make_tron_payload(self, from_addr="TSender", to_addr="TReceiverAddress",
                           value="1000000", valid_before=None):
        """Helper to create a TronPaymentPayload wrapped in PaymentPayload."""
        if valid_before is None:
            valid_before = str(int(time.time()) + 3600)

        auth_data = {
            "from": from_addr,
            "to": to_addr,
            "value": value,
            "tokenContract": TRON_USDT_NILE,
            "nonce": "0xtest123",
            "validBefore": valid_before,
            "chainId": TRON_NILE_CHAIN_ID,
        }

        # Create the signature from the hash
        sig = _create_tron_authorization_hash(auth_data)

        tron_payload = TronPaymentPayload(
            signature=sig,
            authorization=TronTransferAuthorization(**auth_data),
        )

        return PaymentPayload(
            x402_version=1,
            scheme="exact",
            network="tron-nile",
            payload=tron_payload,
        )

    @pytest.mark.asyncio
    async def test_verify_valid_payment(self, facilitator, sample_tron_requirements):
        """Valid payment passes verification."""
        payload = self._make_tron_payload(
            to_addr=sample_tron_requirements.pay_to,
            value=sample_tron_requirements.max_amount_required,
        )

        # Mock the httpx call to avoid network dependency
        with patch("x402_a2a.core.tron.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=Exception("no network"))
            mock_client_cls.return_value = mock_client

            result = await facilitator.verify(payload, sample_tron_requirements)

        assert result.is_valid is True
        assert result.payer == "TSender"

    @pytest.mark.asyncio
    async def test_verify_recipient_mismatch(self, facilitator, sample_tron_requirements):
        """Payment to wrong recipient fails verification."""
        payload = self._make_tron_payload(
            to_addr="TWrongAddress",
            value="1000000",
        )

        result = await facilitator.verify(payload, sample_tron_requirements)

        assert result.is_valid is False
        assert "Recipient mismatch" in result.invalid_reason

    @pytest.mark.asyncio
    async def test_verify_insufficient_amount(self, facilitator, sample_tron_requirements):
        """Payment with insufficient amount fails verification."""
        payload = self._make_tron_payload(
            to_addr=sample_tron_requirements.pay_to,
            value="500000",  # Less than required 1000000
        )

        result = await facilitator.verify(payload, sample_tron_requirements)

        assert result.is_valid is False
        assert "Insufficient amount" in result.invalid_reason

    @pytest.mark.asyncio
    async def test_verify_expired_payment(self, facilitator, sample_tron_requirements):
        """Expired payment fails verification."""
        payload = self._make_tron_payload(
            to_addr=sample_tron_requirements.pay_to,
            value="1000000",
            valid_before=str(int(time.time()) - 100),  # Already expired
        )

        result = await facilitator.verify(payload, sample_tron_requirements)

        assert result.is_valid is False
        assert "expired" in result.invalid_reason.lower()

    @pytest.mark.asyncio
    async def test_verify_dict_payload(self, facilitator, sample_tron_requirements):
        """Verification works when payload is a dict (JSON deserialized)."""
        valid_before = str(int(time.time()) + 3600)
        auth_data = {
            "from": "TSender",
            "to": sample_tron_requirements.pay_to,
            "value": "1000000",
            "tokenContract": TRON_USDT_NILE,
            "nonce": "0xtest",
            "validBefore": valid_before,
            "chainId": TRON_NILE_CHAIN_ID,
        }
        sig = _create_tron_authorization_hash(auth_data)

        payload = PaymentPayload(
            x402_version=1,
            scheme="exact",
            network="tron-nile",
            payload={
                "signature": sig,
                "authorization": auth_data,
            },
        )

        with patch("x402_a2a.core.tron.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=Exception("no network"))
            mock_client_cls.return_value = mock_client

            result = await facilitator.verify(payload, sample_tron_requirements)

        assert result.is_valid is True


# ============================================================
# TronFacilitator settlement tests
# ============================================================


class TestTronFacilitatorSettle:
    """Tests for TronFacilitator.settle() method."""

    @pytest.mark.asyncio
    async def test_settle_no_private_key(self):
        """Settlement fails gracefully when no private key is configured."""
        facilitator = TronFacilitator(
            settlement_private_key="",
            network="tron-nile",
        )

        auth = TronTransferAuthorization(
            **{
                "from": "TSender",
                "to": "TReceiver",
                "value": "100",
                "tokenContract": TRON_USDT_NILE,
                "nonce": "0x1",
                "validBefore": "9999999999",
                "chainId": TRON_NILE_CHAIN_ID,
            }
        )
        payload = PaymentPayload(
            x402_version=1,
            scheme="exact",
            network="tron-nile",
            payload=TronPaymentPayload(signature="0xsig", authorization=auth),
        )
        req = PaymentRequirements(
            scheme="exact",
            network="tron-nile",
            asset=TRON_USDT_NILE,
            pay_to="TReceiver",
            max_amount_required="100",
            resource="/x",
            description="",
            mime_type="application/json",
            max_timeout_seconds=60,
        )

        result = await facilitator.settle(payload, req)

        assert result.success is False
        assert "No settlement private key" in result.error_reason
