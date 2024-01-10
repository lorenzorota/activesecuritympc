# ActiveSecurityMPC

ActiveSecurityMPC is an active security compiler for passively secure Multiparty Computation (MPC) protocols implemented to work specifically with Python >=3.10. This project serves as a proof of concept and aims to simplify the implementation of active security components on top of existing passively secure MPC protocol implementations. The current version requires users to manually implement active security components, much of which is boilerplate code, whereas in a future update this is aspired to be automated.

## Installation

To get started with ActiveSecurityMPC, follow these steps:

1. Clone the repository using the following command:

    ```bash
    git clone --recursive git@github.com:lorenzorota/activesecuritympc.git
    ```

    Ensure to use the --recursive flag to clone the repository along with its submodules.

2. Install the required dependencies by running:

    ```bash
    pip install -r requirements.txt
    ```

    It's advisable to perform this step inside a virtual environment to manage the project-specific dependencies.

## Usage

Once you have installed the necessary dependencies, you can explore the provided example under `examples.sum_protocol`. To run the example for 3 parties, use the following command:

```bash
bash demo.sh
```

This will execute the case study implementation for the sum protocol with 3 parties, showcasing the functionality of ActiveSecurityMPC.

## Contributing

ActiveSecurityMPC is an open-source project, and contributions are welcome. If you encounter issues, have ideas for improvements, or want to contribute actively to the project, please feel free to open an issue or submit a pull request.

## License

tbd.
