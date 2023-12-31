import argparse
import logging
import multiprocessing
import random
import subprocess
import pandas as pd
import ast
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
    return ast.literal_eval(out[-1])


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
    print(f'Number of CPU cores: {num_cores}')

    dataframes = []
    for j in range(args.ensemble + 1):
        logger.info("Measurement {}".format(j))
        results = []

        pool = multiprocessing.Pool(processes=num_cores)

        for i in range(args.parties):
            rand_val = random.randrange(backend_pf[args.backend])
            results.append(pool.apply_async(run_protocol, args=(i, protocol, rand_val, args)))

        # Close the pool and wait for all processes to finish
        pool.close()
        pool.join()

        data = [result.get() for result in results]

        # Discard the first measurement to make sure everything is 'running'
        if j > 0:
            for i, entry in enumerate(data):
                df = pd.DataFrame(entry, index=[j*i + j])
                df['ensemble'] = j
                dataframes.append(df)
        else:
            logger.info("Discarding first measurement")
    
    if not os.path.exists("benchmarks"):
        os.makedirs("benchmarks")

    stats = pd.concat(dataframes)
    if args.security_level == "active":
        stats.to_csv("benchmarks/sum_active_{}_{}_parties.csv".format(args.backend, args.parties), index=False)
    if args.security_level == "passive":
        stats.to_csv("benchmarks/sum_passive_{}_parties.csv".format(args.parties), index=False)
    
    print("Done")