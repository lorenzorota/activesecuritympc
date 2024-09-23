# ActiveSecurityMPC

ActiveSecurityMPC is an active-security compiler for passively secure Multiparty Computation (MPC) protocols (also known as a passive-to-active security compiler) implemented in Python >=3.10. This project serves as a proof of concept and aims to simplify the implementation of active security components on top of existing passively secure MPC protocol implementations. This project is a proof of concept developed as part of my [Master's thesis](https://fse.studenttheses.ub.rug.nl/33067/) at the University of Groningen. End users are required to manually implement active security components, much of which is boilerplate code (see Appendix A of the thesis and the `sum_protocol` example).

## Installation

To get started with ActiveSecurityMPC, make sure to have a stable Rust compiler (as required by the [ZKPyToolkit](https://github.com/lorenzorota/zkpytoolkit) library), and simply install all dependencies as follows:

```bash
pip install -r requirements.txt
```

It's advisable to perform this step inside a virtual environment to manage the project-specific dependencies.

## Usage

Once you have installed the necessary dependencies, you can explore the provided example under `examples.sum_protocol`. To run the example for 3 parties, use the following command:

```bash
bash run_demo.sh
```

This will execute the case study implementation for the sum protocol with 3 parties, showcasing the active-security compiler.

## Benchmarking

A simple benchmarking script is included, which allows you to assess its performance. To run the benchmark, use the following command:

```bash
bash run_benchmark.sh
```

This script will provide insights into the passively secure MPC protocol, as well as the actively secure protocol obtained via ActiveSecurityMPC. Feel free to customize the benchmarking parameters based on your requirements.

## License

This project is licensed under the **MIT** license. See the `LICENSE` files for more details.

## Acknowledgements

This work was developed at the University of Groningen and TNO (Department of Applied Cryptography & Quantum Algorithms).
