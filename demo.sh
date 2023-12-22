# module load Python/3.10.4-GCCcore-11.3.0
# module load OpenSSL/1.1

# cd  /home4/$USER/test
# source /home4/$USER/test/bin/activate

# Create dir output if it does not exist
if [ ! -d "output" ]; then
    mkdir output
fi

# Execute all instances and redirect outputs
python run.py active_security_mpc.examples.sum_protocol -D -P 3 -I 0 -V 100 -L active --stats > output/out0.txt &
python run.py active_security_mpc.examples.sum_protocol -D -P 3 -I 1 -V 100 -L active > output/out1.txt &
python run.py active_security_mpc.examples.sum_protocol -D -P 3 -I 2 -V 100 -L active > output/out2.txt &
# Wait for all processes to finish
wait
