import argparse
import logging
import multiprocessing
import random
import subprocess
import pandas
import os
import sys

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configure argparse
parser = argparse.ArgumentParser(description="MPC sum problem using additive secret sharing scheme.")
parser.add_argument("-P", "--parties", type=int, help="The number of parties.", required=True)
parser.add_argument("-E", "--ensemble", type=int, default=1, help="The number of instances to run during a measurement")
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

# handler = logging.StreamHandler()
# handler.setLevel(logging.DEBUG)
# logger.addHandler(handler)

def run_protocol(i, protocol, rand_val, args):
    command = [
        "python",
        "run.py",
        f"{protocol}",
        "--idx",
        f"{i}",
        "--value",
        f"{rand_val}",
        "--parties",
        f"{args.parties}",
        "--security-level",
        f"{args.security_level}",
        "--backend",
        f"{args.backend}",
        "--stats"
    ]

    out = None
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
        process.wait()
        out = process.stdout.readlines()
    return out


if __name__ == "__main__":
    args = parser.parse_args()

    # Import types after argparse setup to avoid clashing arguments
    sys.argv = [sys.argv[0]]
    from zkpytoolkit.types import bls12_381_scalar_field_modulus, curve25519_scalar_field_modulus 
    
    # ZKP Backend primefield map
    backend_pf = {
        "groth16": bls12_381_scalar_field_modulus,
        "bulletproofs": curve25519_scalar_field_modulus
    }

    protocol = "active_security_mpc.benchmark"
    protocol_module_name = "{}.{}".format(protocol, args.security_level)

    if not os.path.exists("output"):
        os.makedirs("output")

    # Create a Pool with the number of available CPU cores
    num_cores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=num_cores)
    print(f'Number of CPU cores: {num_cores}')

    results = []

    # Instantiate benchmark of 
    for i in range(args.parties):
        rand_val = random.randrange(backend_pf[args.backend])
        results.append(pool.apply_async(run_protocol, args=(i, protocol, rand_val, args)))

    # Close the pool and wait for all processes to finish
    pool.close()
    pool.join()

    # Optionally, you can get the results if your function returns anything
    for result in results:
        print(result.get())
