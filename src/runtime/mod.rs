use crate::program::{self, CallContractData, Expression, HexString, Program, Statement, Variable};
use crate::{errors, solidity};
use aurora_engine_transactions::legacy::TransactionLegacy;
use aurora_engine_types::types::{Address, Wei};
use aurora_engine_types::U256;
use secp256k1::SecretKey;
use std::collections::HashMap;

pub mod value;
pub mod vm;

pub use value::{Value, ValueType};
pub use vm::{ExecutionProfile, VM};

pub fn execute(program: Program) -> Result<Runtime, errors::RuntimeError> {
    let mut runtime = Runtime::new();

    for statement in program.statements {
        execute_statement(statement, &mut runtime)?
    }

    Ok(runtime)
}

pub fn execute_statement(
    statement: Statement,
    runtime: &mut Runtime,
) -> Result<(), errors::RuntimeError> {
    match statement {
        Statement::Assign { name, expression } => {
            let value = execute_expression(expression, runtime)?;
            if runtime.variables.contains_key(&name) {
                println!("WARN: overwriting variable {}", name);
            }
            runtime.variables.insert(name, value);
        }
        Statement::AssertEq { left, right } => {
            let left = runtime.get_value(left)?;
            let right = runtime.get_value(right)?;
            return if left != right {
                Err(errors::RuntimeError::AssertEqFailed {
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone()),
                })
            } else {
                Ok(())
            };
        }
        Statement::Print { value } => {
            let value = runtime.get_value(value)?;
            let serialized = serde_json::to_value(&value.serializable())?;
            runtime.print_buffer.push(serialized);
        }
    }

    Ok(())
}

pub fn execute_expression(
    expression: Expression,
    runtime: &mut Runtime,
) -> Result<Value, errors::RuntimeError> {
    match expression {
        Expression::CreateAccount {
            initial_balance,
            secret_key,
            initial_nonce,
        } => {
            let initial_balance = parse_u256(&initial_balance)?;
            let signer = match secret_key {
                None => Signer::random(),
                Some(sk_hex) => {
                    let sk = SecretKey::parse_slice(&sk_hex.try_to_bytes()?)?;
                    Signer::new(sk)
                }
            };
            let initial_nonce = initial_nonce.unwrap_or(0);
            runtime.vm.create_address(
                signer.address(),
                Wei::new(initial_balance),
                initial_nonce.into(),
                None,
            );
            Ok(Value::SigningAccount(signer))
        }
        Expression::DeployContract {
            contract,
            signing_account,
            constructor_args,
            value,
        } => {
            let variables = &mut runtime.variables;
            let signer = get_mut_signer(variables, signing_account)?;
            let constructor = match contract {
                program::DeployContractData::ExtJson { extended_json_path } => {
                    solidity::ContractConstructor::from_extended_json(extended_json_path)?
                }
                program::DeployContractData::WithABI {
                    abi_path,
                    compiled_contract_path,
                } => solidity::ContractConstructor::from_abi_and_bin(
                    abi_path,
                    compiled_contract_path,
                )?,
                program::DeployContractData::Raw { evm_bytes } => solidity::ContractConstructor {
                    abi: Default::default(),
                    code: evm_bytes.try_to_bytes()?,
                },
            };
            let nonce = U256::from(signer.use_nonce());
            let mut deploy_tx = match constructor_args {
                None => constructor.deploy_without_constructor(nonce),
                Some(args) => {
                    let mut abi_args = Vec::new();
                    for arg in args {
                        abi_args.push(arg.try_into()?)
                    }
                    constructor.deploy_with_args(nonce, &abi_args)?
                }
            };
            if let Some(value) = value {
                deploy_tx.value = Wei::new(parse_u256(&value)?);
            }
            let (result, profile) = runtime
                .vm
                .submit_transaction_profiled(&signer.secret_key, deploy_tx)?;
            let contract_address = match &result.status {
                aurora_engine::parameters::TransactionStatus::Succeed(bytes) => {
                    Address::try_from_slice(bytes).unwrap()
                }
                other => {
                    return Err(errors::RuntimeError::EVMExecutionFailed(other.clone()));
                }
            };

            let contract = constructor.deployed_at(contract_address);
            Ok(Value::Contract {
                contract,
                deployment_near_gas_used: profile.all_gas(),
                deployment_result: result,
            })
        }
        Expression::CallContract {
            contract,
            signing_account,
            data,
            value,
        } => {
            let nonce = {
                let value = get_mut_signer(&mut runtime.variables, signing_account.clone())?;
                U256::from(value.use_nonce())
            };
            let value = match value {
                None => U256::zero(),
                Some(value_hex) => parse_u256(&value_hex)?,
            };
            let transaction = {
                let address = runtime.get_address(contract.clone())?;
                let mut tx_template = TransactionLegacy {
                    nonce,
                    gas_price: U256::zero(),
                    gas_limit: u64::MAX.into(),
                    to: Some(address),
                    value: Wei::new(value),
                    data: Vec::new(),
                };
                match data {
                    None => tx_template,
                    Some(data) => match data {
                        CallContractData::Raw(data_hex) => {
                            tx_template.data = data_hex.try_to_bytes()?;
                            tx_template
                        }
                        CallContractData::SolidityMethod { name, args } => {
                            let contract = get_contract(&runtime.variables, contract)?;
                            match args {
                                None => contract.call_method_without_args(&name, nonce)?,
                                Some(args) => {
                                    let mut abi_args = Vec::new();
                                    for arg in args {
                                        abi_args.push(arg.try_into()?)
                                    }
                                    contract.call_method_with_args(&name, &abi_args, nonce)?
                                }
                            }
                        }
                    },
                }
            };
            let signer = get_mut_signer(&mut runtime.variables, signing_account)?;
            let (result, profile) = runtime
                .vm
                .submit_transaction_profiled(&signer.secret_key, transaction)?;

            Ok(Value::ContractCallResult {
                near_gas_used: profile.all_gas(),
                result,
            })
        }
        Expression::GetBalance { address } => {
            let address = runtime.get_address(address)?;
            let bytes = runtime.vm.getter_method_call("get_balance", address)?;
            let number = U256::from_big_endian(&bytes);
            Ok(Value::U256(number))
        }
        Expression::GetNonce { address } => {
            let address = runtime.get_address(address)?;
            let bytes = runtime.vm.getter_method_call("get_nonce", address)?;
            let number = U256::from_big_endian(&bytes);
            Ok(Value::U256(number))
        }
        Expression::GetCode { address } => {
            let address = runtime.get_address(address)?;
            let bytes = runtime.vm.getter_method_call("get_code", address)?;
            Ok(Value::Bytes(bytes))
        }
        Expression::GetOutput { contract_call } => {
            let value = runtime.get_value(contract_call)?;
            match value {
                Value::ContractCallResult { result, .. } => match result.status.clone() {
                    aurora_engine::parameters::TransactionStatus::Succeed(bytes) => {
                        Ok(Value::Bytes(bytes))
                    }
                    other => Err(errors::RuntimeError::EVMExecutionFailed(other)),
                },
                other => Err(errors::RuntimeError::TypeMismatch {
                    expected: ValueType::ContractCallResult,
                    received: other.typ(),
                }),
            }
        }
        Expression::Primitive(primitive) => match primitive {
            program::Primitive::Bool(x) => Ok(Value::Bool(x)),
            program::Primitive::String(x) => Ok(Value::String(x)),
            program::Primitive::U256(x) => {
                let number = parse_u256(&x)?;
                Ok(Value::U256(number))
            }
            program::Primitive::Bytes(x) => {
                let bytes = x.try_to_bytes()?;
                Ok(Value::Bytes(bytes))
            }
            program::Primitive::Variable(v) => runtime.get_value(v).cloned(),
        },
    }
}

fn parse_u256(hex_str: &HexString) -> Result<U256, hex::FromHexError> {
    let bytes = hex_str.try_to_bytes()?;
    Ok(U256::from_big_endian(&bytes))
}

pub struct Runtime {
    pub vm: VM,
    pub variables: HashMap<String, Value>,
    pub print_buffer: Vec<serde_json::Value>,
}

impl Runtime {
    pub fn get_value(&self, v: Variable) -> Result<&Value, errors::RuntimeError> {
        let value = self
            .variables
            .get(&v.0)
            .ok_or(errors::RuntimeError::UnknownVariable(v))?;
        Ok(value)
    }

    pub fn get_address(&self, v: Variable) -> Result<Address, errors::RuntimeError> {
        let value = self.get_value(v)?;
        let address = match value {
            Value::Contract { contract, .. } => contract.address,
            Value::SigningAccount(signer) => signer.address(),
            Value::Bytes(bytes) => Address::try_from_slice(bytes)
                .map_err(|_| errors::TokenParseError::InvalidAddress)?,
            other => {
                return Err(errors::RuntimeError::TypeMismatch {
                    expected: ValueType::Bytes,
                    received: other.typ(),
                });
            }
        };
        Ok(address)
    }
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            vm: vm::deploy_evm(),
            variables: HashMap::new(),
            print_buffer: Vec::new(),
        }
    }
}

fn get_mut_signer(
    variables: &mut HashMap<String, Value>,
    var: Variable,
) -> Result<&mut Signer, errors::RuntimeError> {
    let value = variables
        .get_mut(&var.0)
        .ok_or(errors::RuntimeError::UnknownVariable(var))?;
    match value {
        Value::SigningAccount(signer) => Ok(signer),
        other => Err(errors::RuntimeError::TypeMismatch {
            expected: ValueType::SigningAccount,
            received: other.typ(),
        }),
    }
}

fn get_contract(
    variables: &HashMap<String, Value>,
    var: Variable,
) -> Result<&solidity::DeployedContract, errors::RuntimeError> {
    let value = variables
        .get(&var.0)
        .ok_or(errors::RuntimeError::UnknownVariable(var))?;
    match value {
        Value::Contract { contract, .. } => Ok(contract),
        other => Err(errors::RuntimeError::TypeMismatch {
            expected: ValueType::DeployedContract,
            received: other.typ(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub nonce: u64,
    pub secret_key: SecretKey,
}

impl Signer {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            nonce: 0,
            secret_key,
        }
    }

    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::random(&mut rng);
        Self::new(sk)
    }

    pub fn use_nonce(&mut self) -> u64 {
        let nonce = self.nonce;
        self.nonce += 1;
        nonce
    }

    pub fn address(&self) -> Address {
        let pk = secp256k1::PublicKey::from_secret_key(&self.secret_key);
        let hash = aurora_engine_sdk::keccak(&pk.serialize()[1..]);
        Address::try_from_slice(&hash[12..]).unwrap()
    }
}
