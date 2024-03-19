import logging
import importlib
import os

from zkpytoolkit import ZKP
from zkpytoolkit.types import bls12_381_scalar_field_modulus
from zkpytoolkit.types import bn256_scalar_field_modulus
from zkpytoolkit.types import curve25519_scalar_field_modulus
from zkpytoolkit.types import Private, Public, Array, field
if not ZKP._instance:
    raise RuntimeError("ZKP needs to be instantiated before loading this script.")
elif ZKP._instance.modulus == bls12_381_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bls12_381.commit import commit_field as commit
elif ZKP._instance.modulus == bn256_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bn256.commit import commit_field as commit
elif ZKP._instance.modulus == curve25519_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.ristretto255.commit import commit_field as commit
from active_security_mpc.utilities import *
from active_security_mpc.template.protocol import ActiveProtocol, stats_measure_communication, stats_time_accumulator


zkp = ZKP._instance # defined globally across all modules at runtime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Driver code
class Sum(ActiveProtocol):
    def __init__(self, local_idx, local_port, parties, enable_stats):
        super().__init__(local_idx, local_port, parties, enable_stats, field_type=field)

        global protocol_0, protocol_1, protocol_2
        global auth_protocol_0, auth_protocol_1, auth_protocol_2

        # Import protocols
        decompositions_module = ".decompositions.protocol_{}p".format(parties)
        zk_statements_module = ".zk_statements.protocol_{}p".format(parties)
        try:
            mod = importlib.import_module(decompositions_module, "active_security_mpc.benchmark")
            protocol_0 = getattr(mod, "protocol_0")
            protocol_1 = getattr(mod, "protocol_1")
            protocol_2 = getattr(mod, "protocol_2")
        except ImportError:
            print(f"Error: Unable to import module '{decompositions_module}'")
            exit(1)
        try:
            mod = importlib.import_module(zk_statements_module, "active_security_mpc.benchmark")
            auth_protocol_0 = getattr(mod, "auth_protocol_0")
            auth_protocol_1 = getattr(mod, "auth_protocol_1")
            auth_protocol_2 = getattr(mod, "auth_protocol_2")
        except ImportError:
            print(f"Error: Unable to import module '{zk_statements_module}'")
            exit(1)

    @stats_measure_communication('setup_communication')
    @stats_time_accumulator('setup_time')
    async def setup(self):
        """Compiler setup"""
        N = self.parties

        logger.info("[Entering setup phase]")
        # Step 0(a): Compiling the ZK-statements
        logger.info("Running step 0(a).")
        functions = [auth_protocol_0, auth_protocol_1, auth_protocol_2]
        includes = [commit, N, protocol_0, protocol_1, protocol_2]
        self.compile_zkps(functions, includes, globals(), locals())

        # Step 0(b): Performing a trusted up
        if zkp.backend in ["groth16"]:
            logger.info("Running step 0(b).")
            await self.trusted_setup(functions)

    @stats_measure_communication('engagement_communication')
    @stats_time_accumulator('engagement_time')
    async def engage(self, secret):
        """Protocol engagement"""
        logger.info("[Entering protocol engagement phase]")
        i = self.local_idx
        N = self.parties

        # Step 1: Obtain randomness
        logger.info("Running step 1.")
        coins = self.secure_coin_flipping(N - 1)
        logger.debug("Private coins: \n{}".format(coins))

        # Step 2(b)i: Compute protocol_0 functionality
        logger.info("Running step 2(b)i.")
        outputs_0 = protocol_0(secret, coins, i, field(1))
        logger.debug("Private secret shares: \n{}".format(shares_info(outputs_0)))

        # Step 2(b)ii: Compute commitments and blinding factors to outputs of protocol_0
        logger.info("Running step 2(b)ii.")
        my_blindings = self.coin_flipping(2 * N)
        my_commitments = auth_protocol_0(secret, coins, my_blindings, i, field(1))
        commitments = await self.communicate(my_commitments, "broadcast", "protocol_0", "int_list", flatten=True, unflatten=8)
        logger.debug("Private secret share commitments: \n{}".format(commitments_info(my_commitments)))
        logger.debug("Private secret share commitment blinding factors: \n{}".format(blinding_factors_info(my_blindings)))
        logger.debug("Received all commitments: \n{}".format(commitments_info(commitments)))

        # Step 2(b)iii: Distribute outputs and blinding factors
        logger.info("Running step 2(b)iii.")
        inputs_1 = await self.communicate(outputs_0, "distribute", "engagement", "field")
        blindings_1 = await self.communicate(my_blindings[0::2], "distribute", "blinding_factor_1", "field")
        blindings_2 = await self.communicate(my_blindings[1::2], "distribute", "blinding_factor_2", "field")
        blindings = [item for pair in zip(blindings_1, blindings_2) for item in pair]
        logger.debug("Received secret shares: \n{}".format(shares_info(inputs_1)))
        logger.debug("Received secret share commitment blinding factors: \n{}".format(blinding_factors_info(blindings)))

        # Step 2(b)iv: Authenticate protocol_0
        logger.info("Running step 2(b)iv.")
        args_prove = (secret, coins, my_blindings, i, field(1))
        args_verify = (commitments, [[None, None, None, j, field(1)] for j in range(N)])
        await self.authenticate(auth_protocol_0, args_prove, args_verify)

        return inputs_1, blindings, commitments

    @stats_measure_communication('emulation_communication')
    @stats_time_accumulator('emulation_time')
    async def emulate(self, inputs, blindings, all_commitments):
        """Protocol emulation"""
        logger.info("[Entering protocol emulation phase]")
        i = self.local_idx
        N = self.parties

        incoming_commitments = [[comm[j] for comm in all_commitments] for j in range(N)]

        # Step 3(a): Compute and broadcast protocol_1 functionality
        logger.info("Running step 3(a)")
        output_2 = protocol_1(inputs, field(1))
        inputs_2 = await self.communicate(output_2, "broadcast", "protocol_1", "field")
        logger.debug("Received secret shares: \n{}".format(shares_info(inputs_2)))

        # Step 3(b): Authenticate protocol_1
        logger.info("Running step 3(b)")
        args_prove = (inputs, blindings, incoming_commitments[i], field(1))
        args_verify = (inputs_2, [[None, None, incoming_commitments[j], field(1)] for j in range(N)])
        await self.authenticate(auth_protocol_1, args_prove, args_verify)

        # Step 3(a): Compute and broadcast protocol_2 functionality
        logger.info("Running step 3(a)")
        output_2 = protocol_2(inputs_2, field(1))
        final_output = await self.communicate(output_2, "broadcast", "protocol_2", "field")
        logger.debug("Received secret shares: \n{}".format(shares_info(final_output)))

        # Step 3(b): Authenticate protocol_2
        logger.info("Running step 3(b)")
        args_prove = (inputs_2, field(1))
        args_verify = (final_output, [[inputs_2, field(1)] for j in range(N)])
        await self.authenticate(auth_protocol_2, args_prove, args_verify)

        # Termination
        logger.info("[Check final outputs]")
        if all(output == output_2 for output in final_output):
            print(success_message(output_2))
        else:
            raise ValueError(error_message(final_output))

        if self.stats_enabled:
            total_cache_size, folder_sizes = get_dir_size("cache_id_{}".format(self.local_idx))
            self.stats["cache_size"] = total_cache_size
            for key, val in folder_sizes.items():
                self.stats[key + "_size"] = val
