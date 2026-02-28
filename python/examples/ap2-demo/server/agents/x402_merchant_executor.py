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
import os
from typing import override

from a2a.server.agent_execution import AgentExecutor

# Import the executors and wrappers

from x402_a2a.executors import x402ServerExecutor
from .local_facilitator import LocalFacilitator
from .tron_facilitator import TronLocalFacilitator
from x402_a2a.types import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from x402_a2a import FacilitatorClient, x402ExtensionConfig, FacilitatorConfig
from x402_a2a.core.tron import is_tron_network


# ==============================================================================
# 1. Concrete Implementation of the x402 Wrapper
# This class connects the abstract server logic to a specific facilitator.
# Supports both EVM (Base/Ethereum) and Tron networks.
# Extended by Erudite Intelligence LLC (2026-02-28) for Tron support.
# ==============================================================================
class x402MerchantExecutor(x402ServerExecutor):
    """
    A concrete implementation of the x402ServerExecutor that uses a
    facilitator to verify and settle payments for the merchant.

    Supports both EVM and Tron networks — routes to the appropriate
    facilitator based on the payment's network field.
    """

    def __init__(
        self, delegate: AgentExecutor, facilitator_config: FacilitatorConfig = None
    ):
        super().__init__(delegate, x402ExtensionConfig())

        # EVM facilitator
        use_mock = os.getenv("USE_MOCK_FACILITATOR", "true").lower() == "true"
        if use_mock:
            print("--- Using Mock Facilitator (EVM) ---")
            self._evm_facilitator = LocalFacilitator()
        else:
            print("--- Using REAL Facilitator (EVM) ---")
            self._evm_facilitator = FacilitatorClient(facilitator_config)

        # Tron facilitator — Erudite Intelligence LLC
        print("--- Tron Facilitator initialized (EruditePay/MCRN-3) ---")
        self._tron_facilitator = TronLocalFacilitator()

    def _get_facilitator(self, network: str):
        """Route to the correct facilitator based on network."""
        if is_tron_network(network):
            return self._tron_facilitator
        return self._evm_facilitator

    @override
    async def verify_payment(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> VerifyResponse:
        """Verifies the payment with the appropriate facilitator."""
        facilitator = self._get_facilitator(requirements.network)
        response = await facilitator.verify(payload, requirements)
        if response.is_valid:
            print(f"✅ Payment Verified! (network={requirements.network})")
        else:
            print(f"⛔ Payment failed verification. (network={requirements.network})")
        return response

    @override
    async def settle_payment(
        self, payload: PaymentPayload, requirements: PaymentRequirements
    ) -> SettleResponse:
        """Settles the payment with the appropriate facilitator."""
        facilitator = self._get_facilitator(requirements.network)
        response = await facilitator.settle(payload, requirements)
        if response.success:
            print(f"✅ Payment Settled! (network={requirements.network})")
        else:
            print(f"⛔ Payment failed to settle. (network={requirements.network})")
        return response
