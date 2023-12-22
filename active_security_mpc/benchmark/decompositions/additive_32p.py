from zkpytoolkit.types import Private, Public, Array, field #zk_ignore
from zkpytoolkit.EMBED import sum

N: int = 32 # Hardcoded number of parties

# This can be verifiably computed
def get_additive_shares(
    secret: Private[field],
    randomness: Private[Array[field, 31]],
    party_index: Public[int],
    _one: Public[field]
) -> Array[field, 32]:
    """Generate N additive shares from 'secret' over finite field.

    Args:
        secret (Private[field]): The secret.
        randomness (Private[Array[field, 31]]): The randomness for creating secret shares.
        party_index (Public[int]): Index of current party.
        _one (Public[field]): The multiplicative identity.

    Returns:
        Array[field, 32]: The secret shares.
    """
    share_i: field = (secret - sum(randomness))*_one # The _one multiplication is a workaround for a bug that needs to be fixed
    shares: Array[field, 32] = [field(0) for _ in range(N)]
    
    k: int = 0
    last_rand_num: field = randomness[N-2] # Last random number 
    for j in range(N-1): # We cannot go up to N since both branches are evaluated and randomness[N-1] does not exist
        shares[j] = randomness[k] if j != party_index else share_i
        k += 1 if j != party_index else 0
    shares[N-1] = share_i if k == N-1 else last_rand_num
    
    return shares

# This can be verifiably computed
def reconstruct_secret(shares: Private[Array[field, 32]], _one: Public[field]) -> field:
    """Regenerate secret from additive shares.

    Args:
        shares (Private[Array[field, 32]]): The secret shares.
        _one (Public[field]): The number one field element.

    Returns:
        field: The sum of the shares.
    """
    return sum(shares)*_one
