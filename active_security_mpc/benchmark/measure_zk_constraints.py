import importlib
from typing import Any, Callable, List, Union

from zkpytoolkit import ZKP
from zkpytoolkit.types import bls12_381_scalar_field_modulus
from zkpytoolkit.types import bn256_scalar_field_modulus
from zkpytoolkit.types import curve25519_scalar_field_modulus
from zkpytoolkit.types import Private, Public, Array, field
from active_security_mpc.template.protocol import stats_value_accumulator
if not ZKP._instance:
    raise RuntimeError("ZKP needs to be instantiated before loading this script.")
elif ZKP._instance.modulus == bls12_381_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bls12_381.commit import commit_field as commit
elif ZKP._instance.modulus == bn256_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.bn256.commit import commit_field as commit
elif ZKP._instance.modulus == curve25519_scalar_field_modulus:
    from zkpytoolkit.stdlib.commitment.pedersen.ristretto255.commit import commit_field as commit
from active_security_mpc.utilities import * 
from zkpytoolkit import ZKP


zkp = ZKP._instance # defined globally across all modules at runtime

class Sum():
    def __init__(self, local_idx, local_port, parties, enable_stats):
        self.parties = parties
        self.stats_enabled = enable_stats
        self.stats = {'id': local_idx, 'parties': parties}

        global protocol_0, protocol_1, protocol_2, get_additive_shares, reconstruct_secret
        global auth_protocol_0, auth_protocol_1, auth_protocol_2

        # Import protocols
        decompositions_module = ".decompositions.protocol_{}p".format(parties)
        decompositions_additive_module = ".decompositions.additive_{}p".format(parties)
        zk_statements_module = ".zk_statements.protocol_{}p".format(parties)
        try:
            mod = importlib.import_module(decompositions_module, "active_security_mpc.benchmark")
            protocol_0 = getattr(mod, "protocol_0")
            protocol_1 = getattr(mod, "protocol_1")
            protocol_2 = getattr(mod, "protocol_2")
            mod = importlib.import_module(decompositions_additive_module, "active_security_mpc.benchmark")
            get_additive_shares = getattr(mod, "get_additive_shares")
            reconstruct_secret = getattr(mod, "reconstruct_secret")
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

    def _compile(self, fct, includes, global_vars, local_vars):
        """Wrapper function for zkp.compile()"""
        return zkp.compile(fct, includes, global_vars, local_vars)

    def compile_zkps(
            self,
            functions: List[Callable],
            includes: List[Any],
            global_vars: dict,
            local_vars: dict,
        ):
        """Compiles a list of functions into R1CS constraints.

        Args:
            functions (List[Callable]): List of functions to compile.
            includes (List[Any]): List of dependencies. These can be: modules, classes, objects, arrays, functions.
            global_vars (dict): This `must` be the dictionary obtained from the globals() function.
            local_vars (dict): This `must` be the dictionary obtained from the locals() function.
        """
        total_constraints = 0
        for fct in functions:
            constraints = self._compile(fct, includes, global_vars, local_vars)
            self.stats[fct.__name__] = constraints
            total_constraints += constraints
        return total_constraints

    async def run(self, secret: Any, ports_list: List[int]):
        """"""
        N = self.parties

        functions = [protocol_0, protocol_1, protocol_2]
        includes = [commit, N, get_additive_shares, reconstruct_secret]
        total_constraints = self.compile_zkps(functions, includes, globals(), locals())
        self.stats["total_zkp_constraints_no_commit"] = total_constraints

        functions = [auth_protocol_0, auth_protocol_1, auth_protocol_2]
        includes = [commit, N, protocol_0, protocol_1, protocol_2]
        total_constraints = self.compile_zkps(functions, includes, globals(), locals())
        self.stats["total_zkp_constraints_commit"] = total_constraints
