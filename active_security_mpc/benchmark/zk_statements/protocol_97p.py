from zkpytoolkit import ZKP                                                                         #zk_ignore
from zkpytoolkit.types import Private, Public, Array, field                                         #zk_ignore
from zkpytoolkit.types import bls12_381_scalar_field_modulus                                        #zk_ignore
from zkpytoolkit.types import bn256_scalar_field_modulus                                            #zk_ignore
from zkpytoolkit.types import curve25519_scalar_field_modulus                                       #zk_ignore
if not ZKP._instance:                                                                               #zk_ignore
    raise RuntimeError("ZKP needs to be instantiated before loading this script.")                  #zk_ignore
elif ZKP._instance.modulus == bls12_381_scalar_field_modulus:                                       #zk_ignore
    from zkpytoolkit.stdlib.commitment.pedersen.bls12_381.commit import commit_field as commit      #zk_ignore
elif ZKP._instance.modulus == bn256_scalar_field_modulus:                                           #zk_ignore
    from zkpytoolkit.stdlib.commitment.pedersen.bn256.commit import commit_field as commit          #zk_ignore
elif ZKP._instance.modulus == curve25519_scalar_field_modulus:                                      #zk_ignore
    from zkpytoolkit.stdlib.commitment.pedersen.ristretto255.commit import commit_field as commit   #zk_ignore
    
from ..decompositions.protocol_97p import protocol_1, protocol_2, protocol_3

N: int = 97 # Hardcoded number of parties

# Active security components
def engage_protocol_1(
    secret: Private[field],
    randomness: Private[Array[field, 96]],
    blinding_factors: Private[Array[field, 194]],
    party_index: Public[int],
    _one: Public[field],
) -> Array[Array[int, 8], 97]:
    """Engagement of secret in protocol 1."""
    outputs_comm: Array[Array[int, 8], 97] = [[0 for _ in range(8)] for _ in range(N)]
    outputs: Array[field, 97] = protocol_1(secret, randomness, party_index, _one)

    for i in range(N):
        outputs_comm[i] = commit(outputs[i], blinding_factors[2*i:2*i+2])
    return outputs_comm

def auth_protocol_2(
    private_input: Private[Array[field, 97]],
    blinding_factors: Private[Array[field, 194]],
    public_input_comm: Public[Array[Array[int, 8], 97]],
    _one: Public[field],
) -> field:
    """Authenticated emulation of protocol 2."""
    # Verify that the input: `private_shares' is correct
    for i in range(N):
        assert(public_input_comm[i] == commit(private_input[i], blinding_factors[2*i:2*i+2])), "Invalid commitment"

    # Emulate protocol_2
    return protocol_2(private_input, _one)

def auth_protocol_3(
    public_input: Public[Array[field, 97]],
    _one: Public[field],
) -> field:
    """Authenticated emulation of protocol 3."""
    # Since there is no private input, no commitment openings need to be verified

    # Emulate protocol_3
    return protocol_3(public_input, _one)