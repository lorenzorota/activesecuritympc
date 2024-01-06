import logging

from zkpytoolkit import ZKP
from zkpytoolkit.types import bls12_381_scalar_field_modulus
from zkpytoolkit.types import bn256_scalar_field_modulus
from zkpytoolkit.types import curve25519_scalar_field_modulus
from zkpytoolkit.types import Array, field
if not ZKP._instance:
    raise RuntimeError("ZKP needs to be instantiated before loading this script.")
elif ZKP._instance.modulus == bls12_381_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bls12_381.commit import commit_field as commit
elif ZKP._instance.modulus == bn256_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bn256.commit import commit_field as commit
elif ZKP._instance.modulus == curve25519_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.ristretto255.commit import commit_field as commit
from active_security_mpc.utilities import *
from active_security_mpc.template.protocol import ActiveProtocol, stats_time_accumulator

from .decomposition.protocol import protocol_1, protocol_2, protocol_3
from .transformation.protocol import engage_protocol_1, auth_protocol_2, auth_protocol_3


zkp = ZKP._instance # defined globally across all modules at runtime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Driver code
class Sum(ActiveProtocol):
    def __init__(self, local_idx, local_port, parties, enable_stats):
        super().__init__(local_idx, local_port, parties, enable_stats, field_type=field)

    @stats_time_accumulator('setup_time')
    async def setup(self):
        N = self.parties

        logger.info("[Entering setup phase]")
        # 1. Compile the ZKPs
        logger.info("1. Running ZKP compiler")
        functions = [engage_protocol_1, auth_protocol_2, auth_protocol_3]
        includes = [commit, N, protocol_1, protocol_2, protocol_3]
        self.compile_zkps(functions, includes, globals(), locals())

        # 2. Perform a trusted setup (only for groth16 backend at the moment)
        if zkp.backend in ["groth16"]:
            logger.info("2. Performing trusted setup")
            await self.trusted_setup(functions)

    @stats_time_accumulator('engagement_time')
    async def engage(self, secret):
        """Protocol engagement."""
        logger.info("[Entering protocol engagement phase]")
        i = self.local_idx
        N = self.parties

        # 1. Obtain secure private coins
        logger.info("3. Obtaining secure private coins")
        coins = self.secure_coin_flipping(N - 1)
        logger.debug("Private coins: \n{}".format(coins))

        # 2a. Obtain outputs (secret shares) and their commitments via protocol 0.
        logger.info("4a. Obtaining secret shares, commitments and blinding factors")
        blindings = self.coin_flipping(2 * N)
        protocol_1_output = protocol_1(secret, coins, i, field(1))
        protocol_1_comms = engage_protocol_1(secret, coins, blindings, i, field(1))
        logger.debug("Private secret shares: \n{}".format(shares_info(protocol_1_output)))
        logger.debug("Private secret share commitments: \n{}".format(commitments_info(protocol_1_comms)))
        logger.debug("Private secret share commitment blinding factors: \n{}".format(blinding_factors_info(blindings)))

        # 2b. Broadcast commitments
        logger.info("4b. Broadcasting commitments")
        await self.broadcast(protocol_1_comms, "protocol_1_comms", "int_list", flatten=True)
        protocol_2_comms = await self.receive("protocol_1_comms", "int_list", unflatten=8)
        protocol_2_comms.insert(i, protocol_1_comms)
        logger.debug("Received all commitments: \n{}".format(commitments_info(protocol_2_comms)))

        # 2c. Distribute shares and blinding factors
        logger.info("4c. Distributing secret shares and blinding factors")
        await self.distribute(protocol_1_output, N, "engagement", "field")
        protocol_2_input = await self.receive("engagement", "field")
        protocol_2_input.insert(i, protocol_1_output[i])
        await self.distribute(blindings[0::2], N, "blinding_factor_1", "field")
        await self.distribute(blindings[1::2], N, "blinding_factor_2", "field")
        blindings_1 = await self.receive("blinding_factor_1", "field")
        blindings_2 = await self.receive("blinding_factor_2", "field")
        protocol_2_blindings = [item for pair in zip(blindings_1, blindings_2) for item in pair]
        protocol_2_blindings.insert(2*i, blindings[2*i])
        protocol_2_blindings.insert(2*i+1, blindings[2*i+1])
        logger.debug("Received secret shares: \n{}".format(shares_info(protocol_2_input)))
        logger.debug("Received secret share commitment blinding factors: \n{}".format(blinding_factors_info(protocol_2_blindings)))

        # 3. Prove and verify secret is correct w.r.t commitments
        logger.info("5. Prove and verify secret is correct w.r.t commitments")
        logger.debug("Generating proof for `engage_protocol_1`")
        proof = zkp.prove(engage_protocol_1, secret, coins, blindings, i, field(1))
        await self.broadcast(proof, "engage_protocol_1_proof")
        proofs = await self.receive("engage_protocol_1_proof")
        proofs.insert(i, proof)
        logger.debug("Received proofs for `engage_protocol_1`")

        for j in range(N):
            if j != i:
                logger.debug("Verifying proof for `engage_protocol_1` from {}".format(j))
                zkp.store_proof(engage_protocol_1, proofs[j])
                is_valid = zkp.verify(engage_protocol_1, None, None, None, j, field(1), return_value=protocol_2_comms[j])
                assert(is_valid), "Invalid Proof"

        return protocol_2_input, protocol_2_blindings, protocol_2_comms

    @stats_time_accumulator('emulation_time')
    async def emulate(self, input, blindings, all_commitments):
        """Protocol emulation"""
        logger.info("[Entering protocol emulation phase]")
        i = self.local_idx
        N = self.parties

        ## Protocol 2
        logger.info("6. Run protocol 2")
        commitments = [comm[i] for comm in all_commitments]
        protocol_2_output = auth_protocol_2(input, blindings, commitments, field(1))
        await self.broadcast(protocol_2_output, "protocol_2", "field")
        protocol_3_input = await self.receive("protocol_2", "field")
        protocol_3_input.insert(i, protocol_2_output)
        logger.debug("Received secret shares: \n{}".format(shares_info(protocol_3_input)))

        # prove and verify auth_protocol_2 was run correctly w.r.t commitments
        logger.info("7. Authenticate protocol 2")
        logger.debug("Generating proof for `auth_protocol_2`")
        proof = zkp.prove(auth_protocol_2, input, blindings, commitments, field(1))
        await self.broadcast(proof, "auth_protocol_2_proof")
        proofs = await self.receive("auth_protocol_2_proof")
        proofs.insert(i, proof)
        logger.debug("Received proofs for `auth_protocol_2`")

        for j in range(N):
            if j != i:
                logger.debug("Verifying proof for `auth_protocol_2` from {}".format(j))
                zkp.store_proof(auth_protocol_2, proofs[j])
                commitments = [comm[j] for comm in all_commitments]
                is_valid = zkp.verify(auth_protocol_2, None, None, commitments, field(1), return_value=protocol_3_input[j])
                assert(is_valid), "Invalid Proof"

        ## Protocol 3
        logger.info("6. Run protocol 3")
        protocol_3_output = auth_protocol_3(protocol_3_input, field(1))
        await self.broadcast(protocol_3_output, "protocol_3", "field")
        final_output = await self.receive("protocol_3", "field")
        final_output.insert(i, protocol_3_output)
        logger.debug("Received secret shares: \n{}".format(shares_info(final_output)))

        # prove and verify auth_protocol_3 was run correctly w.r.t commitments
        logger.info("7. Authenticate protocol 3")
        logger.debug("Generating proof for `auth_protocol_3`")
        proof = zkp.prove(auth_protocol_3, protocol_3_input, field(1))
        await self.broadcast(proof, "auth_protocol_3_proof")
        proofs = await self.receive("auth_protocol_3_proof")
        proofs.insert(i, proof)
        logger.debug("Received proofs for `auth_protocol_3`")

        for j in range(N):
            if j != i:
                logger.debug("Verifying proof for `auth_protocol_3` from {}".format(j))
                zkp.store_proof(auth_protocol_3, proofs[j])
                commitments = [comm[j] for comm in all_commitments]
                is_valid = zkp.verify(auth_protocol_3, protocol_3_input, field(1), return_value=final_output[j])
                assert(is_valid), "Invalid Proof"

        # Termination
        logger.info("[Check final outputs]")
        if all(output == protocol_3_output for output in final_output):
            print(success_message(protocol_3_output))
        else:
            raise ValueError(error_message(final_output))
