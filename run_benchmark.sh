#!/bin/bash
#SBATCH --time=96:00:00
#SBATCH --partition=regular
#SBATCH --ntasks=25
#SBATCH --job-name=benchmarking-active-security-compiler
#SBATCH --mem=256G

# module load Python/3.10.4-GCCcore-11.3.0

echo "---------------------------------------------------------"
for ((party=3; party<=25; party++)); do
  echo "Benchmarking sum protocol with $party parties"
  
  echo "Running benchmark for sum protocol with passive security"
  python benchmark.py -P "$party" -E 10 -L passive

  echo "Running benchmark for sum protocol with active security using groth16"
  python benchmark.py -P "$party" -E 10 -L active -B groth16

  echo "Running benchmark for sum protocol with active security using bulletproofs"
  python benchmark.py -P "$party" -E 10 -L active -B bulletproofs

  echo "---------------------------------------------------------"
done
