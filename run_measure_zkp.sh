#!/bin/bash
#SBATCH --time=12:00:00
#SBATCH --partition=regular
#SBATCH --ntasks=1
#SBATCH --job-name=measuring-zkp-constraints
#SBATCH --mem=128G

# module load Python/3.10.4-GCCcore-11.3.0

echo "---------------------------------------------------------"
for ((party=3; party<=25; party++)); do
  echo "Measuring number of ZKP constraints with $party parties"
  
  echo "Running measurement for sum protocol with active security using groth16"
  python benchmark.py --measure-zkp -P "$party" -L neither -B groth16

  echo "Running measurement for sum protocol with active security using bulletproofs"
  python benchmark.py --measure-zkp -P "$party" -L neither -B bulletproofs

  echo "---------------------------------------------------------"
done
