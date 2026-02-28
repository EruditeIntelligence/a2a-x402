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
"""Tron-specific payload types for x402 payment protocol.

Author  : Coder1 / Erudite Intelligence LLC
Date    : 2026-02-28
Purpose : Define Tron TRC20 transfer authorization types that parallel
          the EVM EIP-3009 types but use Tron's address format and
          signing conventions.

Tron differences from EVM:
  - Addresses use base58check (T-prefix), not 0x hex
  - Transactions are protobuf-encoded, not RLP
  - Signing uses TRON_MESSAGE_PREFIX, not EIP-712
  - Energy cost replaces gas cost
  - Chain IDs: mainnet=728126428, nile=3448148188, shasta=2494104990

CHANGELOG:
  v1.0.0 (2026-02-28): Initial Tron payment types.
"""

from typing import Optional
from pydantic import BaseModel, Field


class TronTransferAuthorization(BaseModel):
    """Authorization data for a Tron TRC20 token transfer.

    Parallels EIP3009Authorization but uses Tron address format and fields.
    The 'from_' and 'to' fields use Tron base58check addresses (T-prefix).
    """

    from_: str = Field(
        ...,
        alias="from",
        description="Sender Tron address (base58check, T-prefix)",
    )
    to: str = Field(
        ...,
        description="Recipient Tron address (base58check, T-prefix)",
    )
    value: str = Field(
        ...,
        description="Amount in smallest unit (sun for TRX, or token decimals)",
    )
    token_contract: str = Field(
        ...,
        alias="tokenContract",
        description="TRC20 token contract address (base58check)",
    )
    nonce: str = Field(
        ...,
        description="Unique nonce for replay protection (hex string)",
    )
    valid_before: str = Field(
        ...,
        alias="validBefore",
        description="Unix timestamp (seconds) — payment expires after this",
    )
    chain_id: int = Field(
        ...,
        alias="chainId",
        description="Tron chain ID (728126428=mainnet, 3448148188=nile, 2494104990=shasta)",
    )

    model_config = {"populate_by_name": True}


class TronPaymentPayload(BaseModel):
    """Tron-specific payment payload.

    Contains the signed transaction data and authorization details
    for a TRC20 token transfer on the Tron network.
    """

    signature: str = Field(
        ...,
        description="Hex-encoded signature of the transfer authorization",
    )
    authorization: TronTransferAuthorization = Field(
        ...,
        description="Transfer authorization data (from, to, value, token, nonce)",
    )
    raw_transaction: Optional[str] = Field(
        default=None,
        alias="rawTransaction",
        description="Optional hex-encoded raw Tron transaction (protobuf)",
    )

    model_config = {"populate_by_name": True}


# ============================================================
# Tron network constants
# ============================================================

# Well-known TRC20 token contracts
TRON_USDT_MAINNET = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_USDT_NILE = "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj"
TRON_USDT_SHASTA = "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs"

TRON_USDC_MAINNET = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"

# Chain IDs
TRON_MAINNET_CHAIN_ID = 728126428
TRON_NILE_CHAIN_ID = 3448148188
TRON_SHASTA_CHAIN_ID = 2494104990

# Network string → chain ID mapping
TRON_NETWORK_CHAIN_IDS = {
    "tron": TRON_MAINNET_CHAIN_ID,
    "tron-mainnet": TRON_MAINNET_CHAIN_ID,
    "tron-nile": TRON_NILE_CHAIN_ID,
    "tron-testnet": TRON_NILE_CHAIN_ID,
    "tron-shasta": TRON_SHASTA_CHAIN_ID,
}

# Network string → default USDT contract mapping
TRON_DEFAULT_USDT = {
    "tron": TRON_USDT_MAINNET,
    "tron-mainnet": TRON_USDT_MAINNET,
    "tron-nile": TRON_USDT_NILE,
    "tron-testnet": TRON_USDT_NILE,
    "tron-shasta": TRON_USDT_SHASTA,
}

# All known Tron network identifiers
TRON_NETWORKS = frozenset(TRON_NETWORK_CHAIN_IDS.keys())
