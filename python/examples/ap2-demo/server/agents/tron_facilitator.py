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
"""Tron facilitator for x402 A2A payments.

Author  : Coder1 / Erudite Intelligence LLC
Date    : 2026-02-28
Purpose : Implements Tron TRC20 (USDT) payment verification and settlement
          for the A2A x402 extension. Uses the EruditePay facilitator on
          MCRN-3 for verification and TronGrid for on-chain settlement.

Usage:
    from .tron_facilitator import TronLocalFacilitator

    facilitator = TronLocalFacilitator()
    result = await facilitator.verify(payload, requirements)
    result = await facilitator.settle(payload, requirements)

CHANGELOG:
  v1.0.0 (2026-02-28): Initial Tron facilitator implementation.
"""

import logging
import os
from typing import override

from dotenv import load_dotenv
from x402_a2a import FacilitatorClient
from x402_a2a.core.tron import TronFacilitator
from x402_a2a.types import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from x402_a2a.types.tron import TronPaymentPayload

logger = logging.getLogger(__name__)


class TronLocalFacilitator(TronFacilitator):
    """Tron facilitator that connects to the EruditePay MCRN-3 facilitator.

    Extends the base TronFacilitator with environment-based configuration
    suitable for local development and testnet deployment.

    Environment variables:
        TRON_FACILITATOR_URL: URL of EruditePay facilitator (default: http://46.225.31.159:4000)
        TRON_SETTLEMENT_PRIVATE_KEY: Hex private key for on-chain settlement
        TRON_NETWORK: Network identifier (default: tron-nile)

    Example:
        # In your x402 merchant executor:
        class MyMerchantExecutor(x402ServerExecutor):
            def __init__(self, delegate):
                super().__init__(delegate, x402ExtensionConfig())
                self._facilitator = TronLocalFacilitator()

            async def verify_payment(self, payload, requirements):
                return await self._facilitator.verify(payload, requirements)

            async def settle_payment(self, payload, requirements):
                return await self._facilitator.settle(payload, requirements)
    """

    def __init__(self):
        load_dotenv()

        network = os.getenv("TRON_NETWORK", "tron-nile")
        facilitator_url = os.getenv(
            "TRON_FACILITATOR_URL", "http://46.225.31.159:4000"
        )
        settlement_key = os.getenv("TRON_SETTLEMENT_PRIVATE_KEY", "")

        super().__init__(
            facilitator_url=facilitator_url,
            settlement_private_key=settlement_key,
            network=network,
        )

        logger.info(f"TronLocalFacilitator initialized: network={network}")
        logger.info(f"  Facilitator URL: {facilitator_url}")
        logger.info(f"  Settlement key: {'configured' if settlement_key else 'NOT SET'}")

    @override
    async def verify(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> VerifyResponse:
        """Verify with additional logging for development."""
        logger.info("=== TRON FACILITATOR: VERIFY ===")
        logger.info(f"  Network: {requirements.network}")
        logger.info(f"  Asset: {requirements.asset}")
        logger.info(f"  PayTo: {requirements.pay_to}")
        logger.info(f"  Amount: {requirements.max_amount_required}")

        result = await super().verify(payload, requirements)

        if result.is_valid:
            logger.info(f"  Result: VALID (payer={result.payer})")
        else:
            logger.warning(f"  Result: INVALID ({result.invalid_reason})")

        return result

    @override
    async def settle(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> SettleResponse:
        """Settle with additional logging for development."""
        logger.info("=== TRON FACILITATOR: SETTLE ===")

        result = await super().settle(payload, requirements)

        if result.success:
            logger.info(f"  Result: SUCCESS (tx={result.transaction})")
        else:
            logger.warning(f"  Result: FAILED ({result.error_reason})")

        return result
