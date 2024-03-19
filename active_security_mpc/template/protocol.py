import asyncio
import logging
import secrets
from abc import ABC, abstractmethod
import time
from typing import Any, Callable, List, Tuple, Union

from tno.mpc.communication import Pool

from active_security_mpc.utilities import * 
from zkpytoolkit import ZKP


zkp = ZKP._instance # defined globally across all modules at runtime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
pool_logger = logging.getLogger('tno.mpc.communication.pool')
pool_logger.setLevel(logging.CRITICAL)
httphandlers_logger = logging.getLogger('tno.mpc.communication.httphandlers')
httphandlers_logger.setLevel(logging.CRITICAL)
access_logger = logging.getLogger('aiohttp.access')
access_logger.setLevel(logging.CRITICAL)


def stats_time_accumulator(name):
    def decorator(method):
        if asyncio.iscoroutinefunction(method):
            async def wrapper(self, *args, **kwargs):
                if self.stats_enabled:
                    start_time = time.time()
                    result = await method(self, *args, **kwargs)
                    end_time = time.time()
                    self.stats[name] = self.stats.get(name, 0) + (end_time - start_time)
                else:
                    result = await method(self, *args, **kwargs)
                return result
            return wrapper
        else:
            def wrapper(self, *args, **kwargs):
                if self.stats_enabled:
                    start_time = time.time()
                    result = method(self, *args, **kwargs)
                    end_time = time.time()
                    self.stats[name] = self.stats.get(name, 0) + (end_time - start_time)
                else:
                    result = method(self, *args, **kwargs)
                return result
            return wrapper
    return decorator

def stats_measure_communication(name):
    def decorator(method):
        if asyncio.iscoroutinefunction(method):
            async def wrapper(self, *args, **kwargs):
                if self.stats_enabled:
                    start_communication = self.communication_stats()
                    result = await method(self, *args, **kwargs)
                    end_communication = self.communication_stats()
                    self.stats[name] = end_communication - start_communication
                else:
                    result = await method(self, *args, **kwargs)
                return result
            return wrapper
        else:
            def wrapper(self, *args, **kwargs):
                if self.stats_enabled:
                    start_communication = self.communication_stats()
                    result = method(self, *args, **kwargs)
                    end_communication = self.communication_stats()
                    self.stats[name] = end_communication - start_communication
                else:
                    result = method(self, *args, **kwargs)
                return result
            return wrapper
    return decorator

def stats_value_accumulator(name, value_map=None):
    def decorator(method):
        if asyncio.iscoroutinefunction(method):
            async def wrapper(self, *args, **kwargs):
                result = await method(self, *args, **kwargs)
                if self.stats_enabled:
                    mapped_result = value_map(result) if value_map else result
                    self.stats[name] = self.stats.get(name, 0) + mapped_result
                return result
            return wrapper
        else:
            def wrapper(self, *args, **kwargs):
                result = method(self, *args, **kwargs)
                if self.stats_enabled:
                    mapped_result = value_map(result) if value_map else result
                    self.stats[name] = self.stats.get(name, 0) + mapped_result
                return result
            return wrapper
    return decorator


class PassiveProtocol(ABC):
    """A class for building passively secure MPC protocols from a sequential composition.

    Args:
        ABC: Abstract base class
    """

    def __init__(self, local_idx: int, local_port: int, parties: int, enable_stats: bool, field_type: Union[Any, None]=None):
        """Initializes the passively secure MPC protocol.

        Args:
            local_idx (int): Index of the party running the protocol.
            local_port (int): port of the party running the protocol.
            parties (int): The number of parties.
            enable_stats(int): Indicates whether statistics should be generated.
            field_type (Any, optional): Primefield type (this is necessary since it is unknown at runtime). Defaults to None.
        """
        pool = Pool()
        pool.add_http_server(addr="127.0.0.1", port=local_port)

        self.pool = pool
        self.parties = parties
        self.local_idx = local_idx
        self.stats_enabled = enable_stats
        self.field = field_type
        self.stats = {'id': local_idx, 'parties': parties}

    def establish_connections(self, ports: List[int]):
        """Establish the point-to-point connections between the parties

        Args:
            ports (List[int]): The list of ports
        """
        for idx, port in enumerate(ports):
            if idx != self.local_idx:
                self.pool.add_http_client(f"{idx}", addr="127.0.0.1", port=port)

    def communication_stats(self):
        """Return total communication cost"""
        total_bytes_sent = 0
        total_bytes_recv = 0
        if (server := self.pool.http_server) is not None:
            total_bytes_recv = server.total_bytes_recv
        for handler in self.pool.pool_handlers.values():
            total_bytes_sent += handler.total_bytes_sent
        
        return total_bytes_recv + total_bytes_sent

    async def shutdown(self):
        """Gracefully shutdown all connections"""
        # Note: this is copied and modified from the Pool.shutdown() method in tno.mpc.communications.
        total_bytes_sent = 0
        total_bytes_recv = 0
        if (server := self.pool.http_server) is not None:
            await server.shutdown()
            total_bytes_recv = server.total_bytes_recv
        for handler in self.pool.pool_handlers.values():
            await handler.shutdown()
            total_bytes_sent += handler.total_bytes_sent
        self.pool.pool_handlers = {}
        self.pool.handlers_lookup = {}

        if self.stats_enabled:
            self.stats['total_bytes_sent'] = total_bytes_sent
            self.stats['total_bytes_recv'] = total_bytes_recv

    @stats_time_accumulator('total_communication_time')
    async def distribute(
        self,
        items: Any,
        parties: int,
        msg_id: Union[str, None]=None,
        kind:  Union[str, None]=None,
        flatten: bool=False,
    ):
        """Distribute items over point-to-point communication channels

        Args:
            items (Any): Items that are to be distributed (for now these may be ints, strings, bytes, lists and dicts)
            parties (int): The number of parties
            msg_id (Union[str, None], optional): The message identifier. Defaults to None.
            kind (Union[str, None], optional): Type of item, used for converting field elements. Defaults to None.
            flatten (bool, optional): Specifies whether list should be flattened. Defaults to False.
        """
        for idx in range(parties):
            if idx != self.local_idx:
                if kind == "field":
                    await self.pool.send(f"{idx}", int(items[idx]), msg_id=msg_id)
                elif kind == "field_list":
                    if flatten:
                        await self.pool.send(f"{idx}", flatten_list([int(i) for i in items[idx]]), msg_id=msg_id)
                    else:
                        await self.pool.send(f"{idx}", [int(i) for i in items[idx]], msg_id=msg_id)
                elif kind == "int_list":
                    if flatten:
                        await self.pool.send(f"{idx}", flatten_list(items[idx]), msg_id=msg_id)
                    else:
                        await self.pool.send(f"{idx}", items[idx], msg_id=msg_id)
                else:
                    await self.pool.send(f"{idx}", items[idx], msg_id=msg_id)

    @stats_time_accumulator('total_communication_time')
    async def receive(
        self,
        msg_id: Union[str, None]=None,
        kind: Union[str, None]=None,
        handlers: Union[List[str], None]=None,
        unflatten: Union[int, None]=None,
    ) -> List[Any]:
        """Receive items over point-to-point communication channels

        Args:
            msg_id (Union[str, None], optional): The message identifier. Defaults to None.
            kind (Union[str, None], optional): Type of item, used for converting field elements. Defaults to None.
            handlers (Union[List[str], None], optional): List of parties to receive from (by their index). Defaults to None.
            unflatten (Union[int, None], optional): The number of items per list. Defaults to None.

        Returns:
            List[Any]: A list of received items from all parties.
        """
        messages = await self.pool.recv_all(handlers, msg_id)
        received_shares = []
        for msg in messages:
            if kind == "field" and self.field:
                received_shares.append(self.field(msg[1]))
            elif kind == "field_list" and self.field:
                if unflatten:
                    received_shares.append(unflatten_list([self.field(i) for i in msg[1]], unflatten))
                else:
                    received_shares.append([self.field(i) for i in msg[1]])
            elif kind == "int_list":
                if unflatten:
                    received_shares.append(unflatten_list(msg[1], unflatten))
                else:
                    received_shares.append(msg[1])
            else:
                received_shares.append(msg[1])
        return received_shares

    @stats_time_accumulator('total_communication_time')
    async def broadcast(
        self,
        items: Any,
        msg_id: str,
        kind: Union[str, None]=None,
        flatten: bool=False,
    ):
        """Broadcast items to all parties over point-to-point communication channel

        Args:
            items (Any): Items that are to be distributed (for now these may be ints, strings, bytes, lists and dicts)
            msg_id (str): The message identifier
            kind (Union[str, None], optional): Type of item, used for converting field elements. Defaults to None.
            flatten (bool, optional): Specifies whether list should be flattened. Defaults to False.
        """
        if kind == "field":
            await self.pool.broadcast(int(items), msg_id=msg_id)
        elif kind == "field_list":
            if flatten:
                await self.pool.broadcast(flatten_list([int(i) for i in items]), msg_id=msg_id)
            else:
                await self.pool.broadcast([int(i) for i in items], msg_id=msg_id)
        elif kind == "int_list":
            if flatten:
                await self.pool.broadcast(flatten_list(items), msg_id=msg_id)
            else:
                await self.pool.broadcast(items, msg_id=msg_id)
        else:
            await self.pool.broadcast(items, msg_id=msg_id)

    async def communicate(
            self,
            data: Any,
            model: str,
            tag: str,
            data_type: Union[str, None]=None,
            flatten: bool=False,
            unflatten: Union[int, None]=None
        ) -> List[Any]:
        """Wrapper function for simplifying MPC communication.

        Args:
            data (Any): Items that are to be broadcasted or distributed.
            model (str): Either "broadcast" or "distribute".
            tag (str): The message identifier.
            data_type (Union[str, None], optional): Type of item, used for converting field elements.. Defaults to None.
            flatten (bool, optional): Specifies whether list should be flattened. Defaults to False.
            unflatten (Union[int, None], optional): The number of items per list. Defaults to None.

        Returns:
            List[Any]: A list of received items from all parties, including the sent item.
        """
        if model == "broadcast":
            local_item = data
            await self.broadcast(data, tag, data_type, flatten=flatten)
        elif model == "distribute":
            local_item = data[self.local_idx]
            await self.distribute(data, self.parties, tag, data_type, flatten=flatten)
        else:
            raise ValueError("Invalid form of communication specified")
        received_data = await self.receive(tag, data_type, unflatten=unflatten)
        received_data.insert(self.local_idx, local_item)
        return received_data

    def coin_flipping(self, amount: int, bit_size: int=32) -> List[Any]:
        """Private coin-flipping protocol

        Args:
            amount (int): The number of cloin flip ensembles.
            bit_size (int): The number of coin flips. Defaults to 32.

        Returns:
            List[Any]: List of random field elements or integers, specified by amount.
        """
        # We generate private coins using the `secrets` RNG.
        # For convenience, we transform the coins into finite field elements.
        if self.field:
            return [self.field(secrets.randbelow(zkp.modulus)) for _ in range(amount)]
        else:
            return [secrets.randbelow(2**bit_size) for _ in range(amount)]

    @stats_time_accumulator('total_runtime')
    async def run(self, secret: Any, ports_list: List[int]):
        """Entry point for passively secure sequentially composed MPC protocol

        Args:
            secret (Any): The secret input
            ports_list (List[int]): The list of ports of the other parties
        """
        # Establish all connections
        self.establish_connections(ports_list)

        # Run sequential protocol composition
        await self.compose_protocol(secret)
        
        # Gracefully shutdown
        await self.shutdown()

    @abstractmethod
    async def compose_protocol(self, secret: Any):
        """Sequentially compose single-round protocols 

        Args:
            secret (Any): The secret input
        """  
        pass

class ActiveProtocol(PassiveProtocol):
    """Wrapper protocol with functionalities necessary for transforming
    a passively secure protocol implementation into an actively secure protocol. 

    Args:
        PassiveProtocol (ABC): The passively secure base protocol
    """

    def __init__(self, local_idx: int, local_port: int, parties: int, enable_stats: bool, field_type: Union[Any, None]=None):
        """Initializes the passively secure MPC protocol.

        Args:
            local_idx (int): Index of the party running the protocol.
            local_port (int): port of the party running the protocol.
            parties (int): The number of parties.
            enable_stats(int): Indicates whether statistics should be generated.
            field_type (Any, optional): Primefield type (this is necessary since it is unknown at runtime). Defaults to None.
        """ 
        super().__init__(local_idx, local_port, parties, enable_stats, field_type)

    @stats_value_accumulator('total_crs_len', len)
    @stats_time_accumulator('total_crs_generation_time')
    def _generate_crs(self, fct):
        """Wrapper function for zkp.generate_crs()"""
        return zkp.generate_crs(fct)

    async def trusted_setup(self, functions: List[Callable], trustee_id: int=0):
        """Trusted setup through a trusted party.

        Args:
            functions (List[Callable]): List of ZKP-compiled functions that require a trusted setup.
            trustee_id (int, optional): The index of the trusted party. Defaults to 0.
        """
        # Note: This will need to be mediated through MPC for active security.
        # A possible MPC ceremony for groth16 is the powers-of-tau setup.

        if self.local_idx == trustee_id:
            for fct in functions:
                crs = self._generate_crs(fct)
                await self.broadcast(crs, fct.__name__)
                logger.debug("Broadcasted CRS for `{}`".format(fct.__name__))
        else:
            crs_size_accum = 0
            for fct in functions:
                crs = await self.receive(fct.__name__, handlers=[f'{trustee_id}'])
                zkp.store_crs(fct, crs[0])
                logger.debug("Received CRS for `{}`".format(fct.__name__))
                crs_size_accum += len(crs[0])
            if self.stats_enabled:
                self.stats['total_crs_generation_time'] = None
                self.stats['total_crs_len'] = crs_size_accum

    def secure_coin_flipping(self, amount: int, bit_size: int=32) -> List[Any]:
        """Secure private coin-flipping protocol.

        Args:
            amount (int): The number of cloin flip ensembles.
            bit_size (int): The number of coin flips. Defaults to 32.

        Returns:
            List[Any]: List of random field elements or integers, specified by amount.
        """
        # Note: This will need to be mediated through MPC for active security.
        # A solution could be an MPC variant of Blum's coin tossing protocol.
        # For now, we rely on private coin flipping.

        return self.coin_flipping(amount, bit_size)

    @stats_value_accumulator('total_zkp_constraints')
    @stats_time_accumulator('total_zkp_compile_time')
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
        for fct in functions:
            constraints = self._compile(fct, includes, global_vars, local_vars)
            logger.debug('Constraints count `{}`: {}'.format(fct.__name__, constraints))

    @stats_value_accumulator('total_proof_size', len)
    @stats_time_accumulator('total_proving_time')
    def _prove(self, func, *args, **kwargs):
        """Wrapper function for zkp.prove()"""
        return zkp.prove(func, *args, **kwargs)
    
    @stats_time_accumulator('total_verification_time')
    def _verify(self, func, *args, return_value=None, **kwargs):
        """Wrapper function for zkp.verify()"""
        return zkp.verify(func, *args, return_value=return_value, **kwargs)
    
    async def authenticate(
            self,
            subprotocol: Callable,
            args_prove: Tuple[Any],
            args_verify: Tuple[Any],
        ):
        """Authenticate subprotocol by proving and verifying the ZK-statement.

        Args:
            subprotocol (Callable): The subprotocol to be authenticated.
            args_prove (Tuple[Any]): The prover statement, i.e. instances and witnesses.
            args_verify (Tuple[Any]): The verifier statement, i.e. instances.
        """
        i = self.local_idx
        N = self.parties
        proof = self._prove(subprotocol, *args_prove)
        proofs = await self.communicate(proof, "broadcast", subprotocol.__name__)

        # Assume that in args_verify the first element is the return value
        for j in range(N):
            if j != i:
                zkp.store_proof(subprotocol, proofs[j])
                validity = self._verify(subprotocol, *args_verify[1][j], return_value=args_verify[0][j])
                assert(validity), "Invalid Proof"

    @stats_time_accumulator('total_runtime')
    async def run(self, secret: Any, ports_list: List[int]):
        """Entry point for actively secure sequentially composed MPC protocol.

        Args:
            secret (Any): The secret input.
            ports_list (List[int]): The list of ports of the other parties.
        """
        # Establish all connections
        self.establish_connections(ports_list)

        # 1. Active security compiler setup
        await self.setup()

        # 2. Engagement phase
        output, blindings, commitments = await self.engage(secret)

        # 3. Emulation phase
        await self.emulate(output, blindings, commitments)

        # Gracefully shutdown
        await self.shutdown()

    async def compose_protocol(self, secret: int):
        raise NotImplementedError("This function is not used for building an actively secure protocol.")

    @abstractmethod
    async def setup(self):
        """Active security compiler setup."""
        pass

    @abstractmethod
    async def engage(self, secret):
        """Protocol engagement."""
        pass

    @abstractmethod
    async def emulate(self, input, blindings, all_commitments):
        """Protocol emulation."""
        pass
