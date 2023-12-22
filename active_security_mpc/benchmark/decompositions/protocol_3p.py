from .additive_3p import get_additive_shares
from .additive_3p import reconstruct_secret
from zkpytoolkit.types import Private, Public, Array, field #zk_ignore

# Define all single-round sequential subprotocols

def protocol_1(
    secret: Private[field],
    rand: Private[Array[field, 2]],
    local_idx: Public[int],
    _one: Public[field],
) -> Array[field, 3]:
    """Protocol 1 generates the secret shares.

    The resulting shares get privately distributed among the parties.

    Args:
        secret (Private[field]): The secret input.
        rand (Private[Array[field, 2]]): Randomness needed for creating secret shares.
        local_idx (Public[int]): Index of the party running the protocol.
        _one (Public[field]): The multiplicative identity.

    Returns:
        Array[field, 3]: The secret shares.
    """
    return get_additive_shares(secret, rand, local_idx, _one)

def protocol_2(
    mixed_shares: Private[Array[field, 3]],
    _one: Public[field],
) -> field:
    """Protocol 2 combines all the received secret shares and initial secret.

    The resulting combination gets broadcasted to all parties.

    Args:
        mixed_shares (Private[Array[field, 3]]): The received secret shares (including the initial secret).
        _one (Public[field]): The multiplicative identity.

    Returns:
        field: The combination of received secret shares and the secret.
    """
    return reconstruct_secret(mixed_shares, _one)

def protocol_3(
    final_shares: Private[Array[field, 3]],
    _one: Public[field],
) -> field:
    """Protocol 3 obtains the sum of all secrets by combining all secret shares combinations.

    The resulting combination gets broadcasted to all parties.

    Args:
        final_shares (Private[Array[field, 3]]): The received combinations (including the locally produced one).
        _one (Public[field]): The multiplicative identity.

    Returns:
        field: The sum of all initial secrets.
    """
    return reconstruct_secret(final_shares, _one)
