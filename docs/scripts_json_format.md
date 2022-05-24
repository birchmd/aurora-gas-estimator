# Aurora Gas Estimator Scripting "Language" -- JSON definition

This is the deprecated format for scripts. To use it, pass the `--json-format` flag to the `aurora-gas-estimator` code.
It is recommended that you used the new format described in `scripts.md` instead because it is much less verbose.

The Aurora Gas Estimator consumes scripts which define an EVM contract interaction.
This document describes the format of these scripts.
It is maintained on a "best effort" basis, so may not always be complete.
The real source of truth for the script definition is the `aurora-gas-estimator` source code.
Specifically, see `src/program.rs`; the `Program` struct is precisely what defines the possible scripts.

The script is a JSON object consisting of an array of "statements".

```json
{
    "statements": [...]
}
```

The estimator executes the statements sequentially; variables must be assigned before they are used.
The list of possible statements is described below.
Statements have a side-effect on the `aurora-gas-estimator` runtime state, but do not return anything.
Some statements may contain "expressions".
An expression may or may not have a side-effect on the runtime, but will always return a value.
The list possible expressions are also given below.

## Statements

### Assign

This statement assigns the value returned by an expression to a named variable.

```json
{
    "Assign": {
        "name": "<VARIABLE NAME>",
        "expression": { ... }
    }
}
```

### AssertEq

This statement checks the values stored in two variables are equal.
It is useful for ensuring your script is running as expected, and thus that the gas measurements will be accurate.

```json
{
    "AssertEq": {
        "left": "<VARIABLE NAME 1>",
        "right": "<VARIABLE NAME 2>"
    }
}
```

### Print

This statement will print the value stored in a variable as part of the estimator's output.
Printing the values returned by `DeployContract` and `CallContract` expressions enables gas measurements.

```json
{
    "Print": {
        "value": "<VARIABLE NAME>"
    }
}
```

## Expressions

### CreateAccount

This expression has the side effect of creating a new account in the runtime's EVM.
The return value of this expression can be used in the `signing_account` field of expressions that create EVM transactions (`DeployContract` and `CallContract`).
Note: if the `secret_key` is not provided then a random will be generated instead.

```json
{
    "CreateAccount": {
        "initial_balance": "<BALANCE IN WEI, WRITTEN IN HEX>",
        "secret_key": "<32 BYTE KEY, WRITTEN IN HEX | null>",
        "initial_nonce": "<STARTING NONCE WRITTEN IN HEX | null>"
    }
}
```

### DeployContract

This expression has the side effect of deploying a contract in the runtime's EVM.
The return value can be used in the `contract` field of a `CallContract` expression.
It can also be printed to see the gas usage and logs from the deployment transaction.

```json
{
    "DeployContract": {
        "contract": { ... },
        "signing_account": "<ACCOUNT VARIABLE>",
        "constructor_args": null | [ ... ],
        "value": "<AMOUNT OF WEI TO ATTACH, WRITTEN IN HEX | null>"
    }
}
```

The `contract` field of this expression defines the EVM bytes used to make the deployment, and the contract ABI (if any).
Possible values include:
- `"Raw": { "evm_bytes": "0x..." }` to give the deployment bytes directly (no ABI provided)
- `"ExtJson": { "extended_json_path": "path/to/file" }` to load the data from an extended JSON artifact (e.g. as produced by Hardhat)
- `"WithABI": { "abi_path": "...", "compiled_contract_path": "..." }` to load the data from separate ABI and bin files (e.g. as produced by `solc`).

The `constructor_args` field is `null` when the contract has no constructor, or lists the arguments to pass to the constructor (e.g. `{ "Address": "0x..." }`).


### CallContract

This expression has the side effect of calling a contract already deployed in the runtime's EVM.
It can also be used to transfer ETH between addresses.
Printing the return value of this expression is done to see the gas usage and logs of the transaction.

```json
{
    "CallContract": {
        "contract": "<CONTRACT VARIABLE>",
        "signing_account": "<ACCOUNT VARIABLE>",
        "data": null | { ... },
        "value": "<AMOUNT OF WEI TO ATTACH, WRITTEN IN HEX | null>"
    }
}
```

The `data` field is `null` when no bytes need to be passed as input to the contract (or in the case of an ETH transfer). Otherwise, it can include raw bytes to pass as input, or the name and arguments to call method of a solidity contract (in this case the contract must have been deployed with an ABI):
- `{ "Raw": "0x..." }`
- `{ "SolidityMethod": { "name": "<METHOD NAME>", "args": null | [...] } }`

In the solidity case, the arguments can be `null` (method takes no arguments) or an array, similar to the `constructor_args` field of the `DeployContract` expression.

### GetBalance, GetNonce, GetCode

These expressions do not have any side-effect on the runtime.
They simply query the property from the runtime's EVM and return it.
These expressions can be useful in combination with `AssertEq` statements to validate the execution has happened as expected.

```json
{
    "GetBalance": {
        "address": "<ACCOUNT VARIABLE>"
    }
}
{
    "GetNonce": {
        "address": "<ACCOUNT VARIABLE>"
    }
}
{
    "GetCode": {
        "address": "<CONTRACT VARIABLE>"
    }
}
```

### GetOutput

This expression also has not side effect.
It simply returns the bytes returned by a previous EVM transaction (caused by a `CallContract` expression).
These expressions can be useful in combination with `AssertEq` statements to validate the execution has happened as expected.

```json
{
    "GetOutput": {
        "contract_call": "<CALL VARIABLE>"
    }
}
```

### Primitive

This expression allows you to declare a primitive value (bytes, numbers, etc) directly.
It is useful in combination with `AssertEq` statements that also involve a query.
The primitive allows you to declare the expected result of the query.

```json
{ "Bytes": "0x..." }
{ "Variable": "<VARIABLE NAME>" }
{ "U256": "0x..." }
{ "String": "<SOME STRING>" }
{ "Bool": true | false }
```
