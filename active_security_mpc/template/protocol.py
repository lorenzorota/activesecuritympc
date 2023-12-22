import logging
import secrets
from abc import ABC, abstractmethod
import time
from typing import Any, Callable, List, Union

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

    async def shutdown(self):
        """Gracefully shutdown all connections"""
        await self.pool.shutdown()

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

    async def trusted_setup(self, functions: List[Callable], trustee_id: int=0):
        """Trusted setup through a trusted party.

        Args:
            functions (List[Callable]): List of ZKP-compiled functions that require a trusted setup.
            trustee_id (int, optional): The index of the trusted party. Defaults to 0.
        """
        # Note: This will need to be mediated through MPC for active security.
        # A possible MPC ceremony for groth16 is the powers-of-tau setup.

        if self.local_idx == trustee_id:
            time_accum = 0
            crs_size_accum = 0
            for fct in functions:
                start_time = time.time()
                crs = zkp.generate_crs(fct)
                end_time = time.time()
                await self.broadcast(crs, fct.__name__)
                logger.debug("Broadcasted CRS for `{}`".format(fct.__name__))
                time_accum += (end_time - start_time)
                crs_size_accum += len(crs)
            self.stats['total_crs_generation_time'] = time_accum
            self.stats['total_crs_len'] = crs_size_accum
        else:
            crs_size_accum = 0
            for fct in functions:
                crs = await self.receive(fct.__name__, handlers=[f'{trustee_id}'])
                zkp.store_crs(fct, crs[0])
                logger.debug("Received CRS for `{}`".format(fct.__name__))
                crs_size_accum += len(crs)
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
        constraints_accum = 0
        time_accum = 0
        for fct in functions:
            start_time = time.time()
            constraints = zkp.compile(fct, includes, global_vars, local_vars)
            end_time = time.time()
            logger.debug('Constraints count `{}`: {}'.format(fct.__name__, constraints))
            constraints_accum += constraints
            time_accum += (end_time - start_time)
        if self.stats_enabled:
            self.stats['total_zkp_constraints'] = constraints_accum
            self.stats['total_zkp_compile_time'] = time_accum

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
