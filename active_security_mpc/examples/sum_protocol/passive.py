import logging

from zkpytoolkit.types import field
from active_security_mpc.utilities import *
from active_security_mpc.template.protocol import PassiveProtocol

from .decomposition.protocol import protocol_0, protocol_1, protocol_2

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Driver code
class Sum(PassiveProtocol):
    def __init__(self, local_idx, local_port, parties, enable_stats):
        super().__init__(local_idx, local_port, parties, enable_stats, field_type=field)

    async def compose_protocol(self, secret):
        """Sequential protocol composition"""
        i = self.local_idx
        N = self.parties

        coins = self.coin_flipping(N - 1)

        ## Protocol 0 (pre-processing)
        protocol_0_output = protocol_0(secret, coins, i, field(1))
        protocol_1_input = await self.communicate(protocol_0_output, "distribute", "protocol_0", "field")

        ## Protocol 1
        protocol_1_output = protocol_1(protocol_1_input, field(1))
        protocol_2_input = await self.communicate(protocol_1_output, "broadcast", "protocol_1", "field")

        ## Protocol 2
        protocol_2_output = protocol_2(protocol_2_input, field(1))
        final_output = await self.communicate(protocol_2_output, "broadcast", "protocol_2", "field")

        # Termination
        logger.info("[Check final outputs]")
        if all(output == protocol_2_output for output in final_output):
            print(success_message(protocol_2_output))
        else:
            raise ValueError(error_message(final_output))
