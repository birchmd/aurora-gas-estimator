# Aurora Gas Estimator

A tool to help with estimating NEAR gas spent by transactions on Aurora.

## Building from source

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- GNU Make (3.81+)
- Node.js (v14+)

### Steps

```
git clone --recurse-submodules https://github.com/birchmd/aurora-gas-estimator.git
cd aurora-gas-estimator/aurora-engine/
make release
cd ..
cargo build --release
```

The produced binary to use in future calls will be located at `target/release/aurora-gas-estimator`.

## Usage

`aurora-gas-estimator` executes scripts that define a sequence of EVM interactions (creating accounts, deploying contracts, calling contracts).
Some examples are found in the `examples/` directory of this repo.
A more complete description of the scripting "language" (its really just JSON) is available at `docs/scripts.md`.

To see the amount of NEAR gas a transaction is estimated to use, use the `Print` statement on a contract deployment or call in a script.
This will add a JSON object in the output of the estimator which includes a `near_gas_used` field.
The gas values are reported in raw gas units, however NEAR gas values are often presented in Tgas.
Simply divide the return value by 10^12 to convert it into Tgas.
For example:

```
aurora-gas-estimator -s examples/simple_contract_call.json | jq '.output[0].DeployedContract.deployment_near_gas_used'
aurora-gas-estimator -s examples/simple_contract_call.json | jq '.output[1].ContractCallResult.near_gas_used'
```

The amount of EVM gas burned is also available in the `result` object under the `gas_used` field.

```
aurora-gas-estimator -s examples/simple_contract_call.json | jq '.output[0].DeployedContract.deployment_result.gas_used'
aurora-gas-estimator -s examples/simple_contract_call.json | jq '.output[1].ContractCallResult.result.gas_used'
```
