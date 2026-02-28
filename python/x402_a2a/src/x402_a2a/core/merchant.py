# Copyright 2025 Google LLC
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
"""Payment requirements creation functions.

Extended by Erudite Intelligence LLC (2026-02-28) to support Tron networks.
"""

from typing import Optional, Any, cast
from x402.common import process_price_to_atomic_amount
from x402.types import Price
from ..types import PaymentRequirements, SupportedNetworks
from ..types.tron import TRON_NETWORKS, TRON_DEFAULT_USDT, TRON_NETWORK_CHAIN_IDS


def create_payment_requirements(
    price: Price,
    pay_to_address: str,
    resource: str,
    network: str = "base",
    description: str = "",
    mime_type: str = "application/json",
    scheme: str = "exact",
    max_timeout_seconds: int = 600,
    output_schema: Optional[Any] = None,
    **kwargs,
) -> PaymentRequirements:
    """Creates PaymentRequirements for A2A payment requests.

    Supports both EVM networks (Base, Ethereum) and Tron networks.
    For Tron networks, the price must be a raw token amount string
    (e.g., "1000000" for 1 USDT) since Tron does not use EIP-712.

    Args:
        price: Payment price. Can be:
            - Money: USD amount as string/int (e.g., "$3.10", 0.10, "0.001") - defaults to USDC
            - TokenAmount: Custom token amount with asset information
            - str: Raw atomic amount for Tron networks (e.g., "1000000")
        pay_to_address: Address to receive the payment (EVM 0x or Tron T-prefix)
        resource: Resource identifier (e.g., "/generate-image")
        network: Blockchain network (default: "base"). Tron networks:
                 "tron", "tron-mainnet", "tron-nile", "tron-testnet", "tron-shasta"
        description: Human-readable description
        mime_type: Expected response content type
        scheme: Payment scheme (default: "exact")
        max_timeout_seconds: Payment validity timeout
        output_schema: Response schema
        **kwargs: Additional fields passed to PaymentRequirements

    Returns:
        PaymentRequirements object ready for x402PaymentRequiredResponse
    """

    # Tron network path — bypass EVM price conversion
    if network in TRON_NETWORKS:
        return _create_tron_requirements(
            price=price,
            pay_to_address=pay_to_address,
            resource=resource,
            network=network,
            description=description,
            mime_type=mime_type,
            scheme=scheme,
            max_timeout_seconds=max_timeout_seconds,
            output_schema=output_schema,
            **kwargs,
        )

    # EVM network path — original behavior
    max_amount_required, asset_address, eip712_domain = process_price_to_atomic_amount(
        price, network
    )

    return PaymentRequirements(
        scheme=scheme,
        network=cast(SupportedNetworks, network),
        asset=asset_address,
        pay_to=pay_to_address,
        max_amount_required=max_amount_required,
        resource=resource,
        description=description,
        mime_type=mime_type,
        max_timeout_seconds=max_timeout_seconds,
        output_schema=output_schema,
        extra=eip712_domain,
        **kwargs,
    )


def _create_tron_requirements(
    price: Price,
    pay_to_address: str,
    resource: str,
    network: str,
    description: str,
    mime_type: str,
    scheme: str,
    max_timeout_seconds: int,
    output_schema: Optional[Any],
    **kwargs,
) -> PaymentRequirements:
    """Build PaymentRequirements for a Tron network.

    For Tron, we skip process_price_to_atomic_amount (which expects EVM
    networks) and directly construct the requirements with Tron token
    addresses and chain metadata.

    Author: Coder1 / Erudite Intelligence LLC — 2026-02-28
    """
    # Determine token contract — use explicit asset from kwargs or default USDT
    asset_address = kwargs.pop("asset", None) or TRON_DEFAULT_USDT.get(network)
    chain_id = TRON_NETWORK_CHAIN_IDS.get(network, 728126428)

    # Price handling: if it's a dollar string like "$1.00", convert to USDT atomic
    # (6 decimals). Otherwise pass through as-is (assumed atomic amount).
    if isinstance(price, str):
        if price.startswith("$"):
            usd_amount = float(price[1:])
            max_amount_required = str(int(usd_amount * 1_000_000))
        else:
            # Assume already in atomic units
            max_amount_required = price
    elif isinstance(price, (int, float)):
        # Treat as USD amount
        max_amount_required = str(int(float(price) * 1_000_000))
    else:
        # TokenAmount or other structured type — use as-is
        max_amount_required = str(price)

    return PaymentRequirements(
        scheme=scheme,
        network=cast(SupportedNetworks, network),
        asset=asset_address,
        pay_to=pay_to_address,
        max_amount_required=max_amount_required,
        resource=resource,
        description=description,
        mime_type=mime_type,
        max_timeout_seconds=max_timeout_seconds,
        output_schema=output_schema,
        extra={
            "chainType": "tron",
            "chainId": chain_id,
            "tokenName": "Tether USD",
            "tokenSymbol": "USDT",
            "tokenDecimals": 6,
        },
        **kwargs,
    )
