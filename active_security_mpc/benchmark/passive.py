import logging
import importlib

from zkpytoolkit.types import field
from active_security_mpc.utilities import *
from active_security_mpc.template.protocol import PassiveProtocol


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Driver code
class Sum(PassiveProtocol):
    def __init__(self, local_idx, local_port, parties, enable_stats):
        super().__init__(local_idx, local_port, parties, enable_stats, field_type=field)

        global protocol_1, protocol_2, protocol_3
        
        # Import protocols
        decompositions_module = ".decompositions.protocol_{}p".format(parties)
        try:
            mod = importlib.import_module(decompositions_module, "active_security_mpc.benchmark")
            protocol_1 = getattr(mod, "protocol_1")
            protocol_2 = getattr(mod, "protocol_2")
            protocol_3 = getattr(mod, "protocol_3")
        except ImportError:
            print(f"Error: Unable to import module '{decompositions_module}'")
            exit(1)

    async def compose_protocol(self, secret):
        """Sequential protocol composition"""
        i = self.local_idx
        N = self.parties

        coins = self.coin_flipping(N - 1)

        ## Protocol 1 (pre-processing)
        protocol_1_output = protocol_1(secret, coins, i, field(1))
        await self.distribute(protocol_1_output, N, "engagement", "field")
        protocol_2_input = await self.receive("engagement", "field")
        protocol_2_input.insert(i, protocol_1_output[i])

        ## Protocol 2
        protocol_2_output = protocol_2(protocol_2_input, field(1))
        await self.broadcast(protocol_2_output, "protocol_2", "field")
        protocol_3_input = await self.receive("protocol_2", "field")
        protocol_3_input.insert(i, protocol_2_output)

        ## Protocol 3
        protocol_3_output = protocol_3(protocol_3_input, field(1))
        await self.broadcast(protocol_3_output, "protocol_3", "field")
        final_output = await self.receive("protocol_3", "field")
        final_output.insert(i, protocol_3_output)

        # Termination
        logger.info("[Check final outputs]")
        if all(output == protocol_3_output for output in final_output):
            print(success_message(protocol_3_output))
        else:
            raise ValueError(error_message(final_output))
