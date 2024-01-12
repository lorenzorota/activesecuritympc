import asyncio
import argparse
import logging 
import importlib
import sys

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configure argparse
parser = argparse.ArgumentParser(description="Active security compiler for passively secure MPC protocols.")
parser.add_argument("protocol", help="Protocol name.")
parser.add_argument("-I", "--idx", type=int, help="Party index argument.", required=True)
parser.add_argument("-V", "--value", type=int, help="Secret value argument.", required=True)
parser.add_argument("-P", "--parties", type=int, default=3, help="The number of parties.")
parser.add_argument(
    "-B",
    "--backend",
    default="groth16",
    help="ZKP backend argument. Defaults to: groth16.",
    choices=["groth16", "bulletproofs"]
)
parser.add_argument(
    "-L",
    "--security-level",
    default="passive",
    help="Set the security level of the MPC protocol. Defaults to: passive.",
    choices=["passive", "active"]
)
parser.add_argument("-D", "--debug", action="store_true", help="Enable debug mode.")
parser.add_argument("-S", "--stats", action="store_true", help="Save statistics from the MPC instance.")    

# Other hardcoded configurations
main_port = 61000
backend_pf = {
    "groth16": "bls12_381",
    "bulletproofs": "curve25519"
}

if __name__ == "__main__":
    args = parser.parse_args()

    # Import ZKP after argparse setup to avoid clashing arguments
    sys.argv = [sys.argv[0]]
    from zkpytoolkit import ZKP

    # Determine which protocol to run:
    protocol_module_name = "{}.{}".format(args.protocol, args.security_level)

    # Configure protocol
    N = int(args.parties)
    local_idx = int(args.idx)
    local_port = main_port + local_idx

    zkp = ZKP(backend_pf[args.backend], args.idx, args.backend, protocol_module_name)

    # Import protocol after setting up zkp instance
    from zkpytoolkit.types import field
    try:
        protocol_module = importlib.import_module(protocol_module_name)
        Sum = getattr(protocol_module, "Sum")
    except ImportError:
        print(f"Error: Unable to import module '{protocol_module_name}'")
        exit(1)

    # Modify logging level of protocol
    if args.debug:
        logging.getLogger("active_security_mpc.template.protocol").setLevel(logging.DEBUG)
        logging.getLogger(protocol_module_name).setLevel(logging.DEBUG)

    sum_protocol = Sum(local_idx, local_port, N, args.stats)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(sum_protocol.run(field(args.value), range(main_port, main_port + N)))
    if args.stats:
        print(sum_protocol.stats)
        
    zkp.cleanup()
