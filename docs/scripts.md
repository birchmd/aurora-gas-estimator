# Aurora Gas Estimator Scripting "Language"

The Aurora Gas Estimator consumes scripts which define an EVM contract interaction.
This document describes the format of these scripts.
It is maintained on a "best effort" basis, so may not always be complete.
The real source of truth for the script definition is the `aurora-gas-estimator` source code.
Specifically, see `src/program.rs`; the `Program` struct is precisely what defines the possible scripts.

A script is a text file consisting of a series of "statements".
The estimator executes the statements sequentially; variables must be assigned before they are used.
The list of possible statements is described below.
Statements have a side-effect on the `aurora-gas-estimator` runtime state, but do not return anything.
Some statements may contain "expressions".
An expression may or may not have a side-effect on the runtime, but will always return a value.
The list possible expressions are also given below.

The syntax for statements and expressions is loosely based on javascript.

## Statements

### Assign

This statement assigns the value returned by an expression to a named variable.

```javascript
let VARIABLE_NAME = EXPRESSION
```

### AssertEq

This statement checks the values stored in two variables are equal.
It is useful for ensuring your script is running as expected, and thus that the gas measurements will be accurate.

```javascript
assert_eq(VARIABLE_NAME_1, VARIABLE_NAME_2)
```

### Print

This statement will print the value stored in a variable as part of the estimator's output.
Printing the values returned by `DeployContract` and `CallContract` expressions enables gas measurements.

```javascript
print(VARIABLE_NAME)
```

## Expressions

### CreateAccount

This expression has the side effect of creating a new account in the runtime's EVM.
The return value of this expression can be used in the `signing_account` field of expressions that create EVM transactions (`DeployContract` and `CallContract`).
Note: if the `secret_key` is not provided then a random will be generated instead.

```javascript
create_account(
    initial_balance=BALANCE_IN_WEI_WRITTEN_IN_HEX,
    secret_key=KEY_WRITTEN_IN_HEX, // optional
    initial_nonce=STARTING_NONCE_WRITTEN_IN_HEX, // optional
)
```

### DeployContract

This expression has the side effect of deploying a contract in the runtime's EVM.
The return value can be used in the `contract` field of a `CallContract` expression.
It can also be printed to see the gas usage and logs from the deployment transaction.

```javascript
deploy_contract(
    contract=CONTRACT_EXPR,
    signer=ACCOUNT_VARIABLE,
    constructor_args=(ARGS), // optional
    value=AMOUNT_OF_WEI_TO_ATTACH_WRITTEN_IN_HEX, // optional
)
```

The `contract` field of this expression defines the EVM bytes used to make the deployment, and the contract ABI (if any).
Possible values include:
- `raw(0x...)` to give the deployment bytes directly (no ABI provided)
- `ext_json(PATH)` to load the data from an extended JSON artifact (e.g. as produced by Hardhat)
- `abi_bin(abi_path=..., bin_path=...)` to load the data from separate ABI and bin files (e.g. as produced by `solc`).

The `constructor_args` field should not be given when the contract has no constructor, or lists the arguments to pass to the constructor (e.g. `address(0x...)`, `uint(0x...)`, `"a string"`).


### CallContract

This expression has the side effect of calling a contract already deployed in the runtime's EVM.
It can also be used to transfer ETH between addresses.
Printing the return value of this expression is done to see the gas usage and logs of the transaction.

```javascript
call_contract(
    contract=CONTRACT_VARIABLE,
    signer=ACCOUNT_VARIABLE,
    data=DATA_EXPR, // optional
    value=AMOUNT_OF_WEI_TO_ATTACH_WRITTEN_IN_HEX, // optional
)
```

The `data` field should not be given when no bytes need to be passed as input to the contract (or in the case of an ETH transfer). Otherwise, it can include raw bytes to pass as input, or the name and arguments to call method of a solidity contract (in this case the contract must have been deployed with an ABI):
- `raw(0x...)`
- `solidity(method=..., args=(...))`

In the solidity case, the args field can be omitted entirely (method takes no arguments) or a list, similar to the `constructor_args` field of the `DeployContract` expression.

### GetBalance, GetNonce, GetCode

These expressions do not have any side-effect on the runtime.
They simply query the property from the runtime's EVM and return it.
These expressions can be useful in combination with `AssertEq` statements to validate the execution has happened as expected.

```javascript
get_balance(ACCOUNT_VARIABLE)
get_nonce(ACCOUNT_VARIABLE)
get_code(ACCOUNT_VARIABLE)
```

### GetOutput

This expression also has not side effect.
It simply returns the bytes returned by a previous EVM transaction (caused by a `CallContract` expression).
These expressions can be useful in combination with `AssertEq` statements to validate the execution has happened as expected.

```javascript
get_output(CALL_VARIABLE)
```

### Primitive

This expression allows you to declare a primitive value (bytes, numbers, etc) directly.
It is useful in combination with `AssertEq` statements that also involve a query.
The primitive allows you to declare the expected result of the query.

```javascript
primitive(bytes(0x...))
primitive(var(VARIABLE_NAME))
primitive(uint(0x...))
primitive("some string")
primitive(true)
primitive(false)
```
