use crate::program::{self, CallContractData, Expression, HexString, Program, Statement, Variable};
use crate::{errors, mocked_external, solidity};
use aurora_engine::fungible_token::{FungibleToken, FungibleTokenMetadata};
use aurora_engine::parameters::SubmitResult;
use aurora_engine_transactions::legacy::{LegacyEthSignedTransaction, TransactionLegacy};
use aurora_engine_types::types::{Address, NEP141Wei, Wei};
use aurora_engine_types::{storage, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use near_primitives::runtime::config_store::RuntimeConfigStore;
use near_primitives::version::PROTOCOL_VERSION;
use near_primitives_core::config::VMConfig;
use near_primitives_core::contract::ContractCode;
use near_primitives_core::profile::ProfileData;
use near_primitives_core::runtime::fees::RuntimeFeesConfig;
use near_vm_logic::{VMContext, VMOutcome};
use near_vm_runner::{MockCompiledContractCache, VMError};
use secp256k1::SecretKey;
use std::collections::HashMap;

const EVM_WASM_BYTES: &[u8; 1024938] = include_bytes!("../aurora-engine/mainnet-release.wasm");
const AURORA_ACCOUNT_ID: &str = "aurora";

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
            vm: deploy_evm(),
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

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    SigningAccount(Signer),
    Contract {
        contract: solidity::DeployedContract,
        deployment_near_gas_used: u64,
        deployment_result: SubmitResult,
    },
    ContractCallResult {
        near_gas_used: u64,
        result: SubmitResult,
    },
    U256(U256),
    Bytes(Vec<u8>),
    String(String),
    Bool(bool),
}

impl Value {
    pub fn typ(&self) -> ValueType {
        match self {
            Self::SigningAccount(_) => ValueType::SigningAccount,
            Self::Contract { .. } => ValueType::DeployedContract,
            Self::ContractCallResult { .. } => ValueType::ContractCallResult,
            Self::U256(_) => ValueType::U256,
            Self::Bytes(_) => ValueType::Bytes,
            Self::String(_) => ValueType::String,
            Self::Bool(_) => ValueType::Bool,
        }
    }

    pub fn serializable(&self) -> SerializableValue {
        match self {
            Value::SigningAccount(signer) => SerializableValue::SigningAccount {
                address: bytes_to_hex(signer.address().as_bytes()),
            },
            Value::Contract {
                contract,
                deployment_near_gas_used,
                deployment_result,
            } => SerializableValue::DeployedContract {
                address: bytes_to_hex(contract.address.as_bytes()),
                deployment_near_gas_used: *deployment_near_gas_used,
                deployment_result: deployment_result.clone().into(),
            },
            Value::ContractCallResult {
                near_gas_used,
                result,
            } => SerializableValue::ContractCallResult {
                near_gas_used: *near_gas_used,
                result: result.clone().into(),
            },
            Value::U256(number) => {
                let mut bytes = [0u8; 32];
                number.to_big_endian(&mut bytes);
                SerializableValue::U256(bytes_to_hex(&bytes))
            }
            Value::Bytes(bytes) => SerializableValue::Bytes(bytes_to_hex(bytes)),
            Value::String(s) => SerializableValue::String(s.clone()),
            Value::Bool(b) => SerializableValue::Bool(*b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SerializableValue {
    SigningAccount {
        address: HexString,
    },
    DeployedContract {
        address: HexString,
        deployment_near_gas_used: u64,
        deployment_result: SerializableSubmitResult,
    },
    ContractCallResult {
        near_gas_used: u64,
        result: SerializableSubmitResult,
    },
    U256(HexString),
    Bytes(HexString),
    String(String),
    Bool(bool),
}

/// `aurora_engine::parameters::SubmitResult` does implement `Serialize`, but the output is not very nice for humans.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SerializableSubmitResult {
    pub status: SerializableTransactionStatus,
    pub gas_used: u64,
    pub logs: Vec<SerializableResultLog>,
}

impl From<aurora_engine::parameters::SubmitResult> for SerializableSubmitResult {
    fn from(result: aurora_engine::parameters::SubmitResult) -> Self {
        Self {
            status: result.status.into(),
            gas_used: result.gas_used,
            logs: result.logs.into_iter().map(Into::into).collect(),
        }
    }
}

/// `aurora_engine::parameters::TransactionStatus` does implement `Serialize`, but the output is not very nice for humans.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SerializableTransactionStatus {
    Succeed(HexString),
    Revert(HexString),
    OutOfGas,
    OutOfFund,
    OutOfOffset,
    CallTooDeep,
}

impl From<aurora_engine::parameters::TransactionStatus> for SerializableTransactionStatus {
    fn from(status: aurora_engine::parameters::TransactionStatus) -> Self {
        match status {
            aurora_engine::parameters::TransactionStatus::Succeed(bytes) => {
                Self::Succeed(bytes_to_hex(&bytes))
            }
            aurora_engine::parameters::TransactionStatus::Revert(bytes) => {
                Self::Revert(bytes_to_hex(&bytes))
            }
            aurora_engine::parameters::TransactionStatus::OutOfGas => Self::OutOfGas,
            aurora_engine::parameters::TransactionStatus::OutOfFund => Self::OutOfFund,
            aurora_engine::parameters::TransactionStatus::OutOfOffset => Self::OutOfOffset,
            aurora_engine::parameters::TransactionStatus::CallTooDeep => Self::CallTooDeep,
        }
    }
}

/// `aurora_engine::parameters::ResultLog` does implement `Serialize`, but the output is not very nice for humans.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SerializableResultLog {
    pub address: HexString,
    pub topics: Vec<HexString>,
    pub data: HexString,
}

impl From<aurora_engine::parameters::ResultLog> for SerializableResultLog {
    fn from(log: aurora_engine::parameters::ResultLog) -> Self {
        Self {
            address: bytes_to_hex(log.address.as_bytes()),
            topics: log.topics.iter().map(|t| bytes_to_hex(t)).collect(),
            data: bytes_to_hex(&log.data),
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> HexString {
    HexString(format!("0x{}", hex::encode(bytes)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    SigningAccount,
    DeployedContract,
    ContractCallResult,
    U256,
    Bytes,
    String,
    Bool,
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

pub struct VM {
    pub aurora_account_id: String,
    pub chain_id: u64,
    pub code: ContractCode,
    pub cache: MockCompiledContractCache,
    pub ext: mocked_external::MockedExternalWithTrie,
    pub context: VMContext,
    pub wasm_config: VMConfig,
    pub fees_config: RuntimeFeesConfig,
    pub current_protocol_version: u32,
}

impl Default for VM {
    fn default() -> Self {
        let aurora_account_id = AURORA_ACCOUNT_ID.to_string();

        let runtime_config_store = RuntimeConfigStore::new(None);
        let runtime_config = runtime_config_store.get_config(PROTOCOL_VERSION);
        let wasm_config = runtime_config.wasm_config.clone();

        Self {
            aurora_account_id,
            chain_id: 1313161556, // Aurora localnet,
            code: ContractCode::new(EVM_WASM_BYTES.to_vec(), None),
            cache: Default::default(),
            ext: mocked_external::MockedExternalWithTrie::new(Default::default()),
            context: VMContext {
                current_account_id: AURORA_ACCOUNT_ID.parse().unwrap(),
                signer_account_id: AURORA_ACCOUNT_ID.parse().unwrap(),
                signer_account_pk: vec![],
                predecessor_account_id: AURORA_ACCOUNT_ID.parse().unwrap(),
                input: vec![],
                block_index: 0,
                block_timestamp: 0,
                epoch_height: 0,
                account_balance: 10u128.pow(25),
                account_locked_balance: 0,
                storage_usage: 100,
                attached_deposit: 0,
                prepaid_gas: 10u64.pow(18),
                random_seed: vec![],
                view_config: None,
                output_data_receivers: vec![],
            },
            wasm_config,
            fees_config: RuntimeFeesConfig::test(),
            current_protocol_version: PROTOCOL_VERSION,
        }
    }
}

impl VM {
    pub fn create_address(
        &mut self,
        address: Address,
        init_balance: Wei,
        init_nonce: U256,
        code: Option<Vec<u8>>,
    ) {
        let trie = &mut self.ext.underlying.fake_trie;

        let balance_key = storage::address_to_key(storage::KeyPrefix::Balance, &address);
        let balance_value = init_balance.to_bytes();

        let nonce_key = storage::address_to_key(storage::KeyPrefix::Nonce, &address);
        let nonce_value = aurora_engine_types::types::u256_to_arr(&init_nonce);

        if let Some(code) = code {
            let code_key = storage::address_to_key(storage::KeyPrefix::Code, &address);
            trie.insert(code_key.to_vec(), code);
        }

        let ft_key = storage::bytes_to_key(
            storage::KeyPrefix::EthConnector,
            &[storage::EthConnectorStorageId::FungibleToken as u8],
        );
        let ft_value = {
            let mut current_ft: FungibleToken = trie
                .get(&ft_key)
                .map(|bytes| FungibleToken::try_from_slice(bytes).unwrap())
                .unwrap_or_default();
            current_ft.total_eth_supply_on_near =
                current_ft.total_eth_supply_on_near + NEP141Wei::new(init_balance.raw().as_u128());
            current_ft
        };

        let aurora_balance_key = [
            ft_key.as_slice(),
            self.context.current_account_id.as_ref().as_bytes(),
        ]
        .concat();
        let aurora_balance_value = {
            let mut current_balance: u128 = trie
                .get(&aurora_balance_key)
                .map(|bytes| u128::try_from_slice(bytes).unwrap())
                .unwrap_or_default();
            current_balance += init_balance.raw().as_u128();
            current_balance
        };

        let proof_key = storage::bytes_to_key(
            storage::KeyPrefix::EthConnector,
            &[storage::EthConnectorStorageId::UsedEvent as u8],
        );

        trie.insert(balance_key.to_vec(), balance_value.to_vec());
        trie.insert(nonce_key.to_vec(), nonce_value.to_vec());
        trie.insert(ft_key, ft_value.try_to_vec().unwrap());
        trie.insert(proof_key, vec![0]);
        trie.insert(
            aurora_balance_key,
            aurora_balance_value.try_to_vec().unwrap(),
        );

        self.context.block_index += 1;
    }

    fn update_context(
        context: &mut VMContext,
        caller_account_id: &str,
        signer_account_id: &str,
        input: Vec<u8>,
    ) {
        context.block_index += 1;
        context.block_timestamp += 1_000_000_000;
        context.input = input;
        context.signer_account_id = signer_account_id.parse().unwrap();
        context.predecessor_account_id = caller_account_id.parse().unwrap();
    }

    pub fn call(
        &mut self,
        method_name: &str,
        caller_account_id: &str,
        input: Vec<u8>,
    ) -> (Option<VMOutcome>, Option<VMError>) {
        self.call_with_signer(method_name, caller_account_id, caller_account_id, input)
    }

    pub fn call_with_signer(
        &mut self,
        method_name: &str,
        caller_account_id: &str,
        signer_account_id: &str,
        input: Vec<u8>,
    ) -> (Option<VMOutcome>, Option<VMError>) {
        Self::update_context(
            &mut self.context,
            caller_account_id,
            signer_account_id,
            input,
        );

        let (maybe_outcome, maybe_error) = near_vm_runner::run(
            &self.code,
            method_name,
            &mut self.ext,
            self.context.clone(),
            &self.wasm_config,
            &self.fees_config,
            &[],
            self.current_protocol_version,
            Some(&self.cache),
        );
        if let Some(outcome) = &maybe_outcome {
            self.context.storage_usage = outcome.storage_usage;
        }

        (maybe_outcome, maybe_error)
    }

    pub fn view_call(
        &self,
        method_name: &str,
        input: Vec<u8>,
    ) -> (Option<VMOutcome>, Option<VMError>) {
        let mut context = self.context.clone();
        let mut ext = self.ext.clone();

        Self::update_context(
            &mut context,
            &self.aurora_account_id,
            &self.aurora_account_id,
            input,
        );

        near_vm_runner::run(
            &self.code,
            method_name,
            &mut ext,
            context,
            &self.wasm_config,
            &self.fees_config,
            &[],
            self.current_protocol_version,
            Some(&self.cache),
        )
    }

    pub fn getter_method_call(
        &self,
        method_name: &str,
        address: Address,
    ) -> Result<Vec<u8>, errors::RuntimeError> {
        let (outcome, maybe_error) = self.view_call(method_name, address.as_bytes().to_vec());
        if let Some(err) = maybe_error {
            return Err(err.into());
        }
        Ok(outcome.unwrap().return_data.as_value().unwrap())
    }

    pub fn submit_transaction_profiled(
        &mut self,
        account: &SecretKey,
        transaction: TransactionLegacy,
    ) -> Result<(SubmitResult, ExecutionProfile), VMError> {
        let calling_account_id = "some-account.near";
        let signed_tx = sign_transaction(transaction, Some(self.chain_id), account);

        let (output, maybe_err) = self.call(
            "submit",
            calling_account_id,
            rlp::encode(&signed_tx).to_vec(),
        );

        if let Some(err) = maybe_err {
            Err(err)
        } else {
            let output = output.unwrap();
            let profile = ExecutionProfile::new(&output);
            let submit_result =
                SubmitResult::try_from_slice(&output.return_data.as_value().unwrap()).unwrap();
            Ok((submit_result, profile))
        }
    }
}

fn deploy_evm() -> VM {
    let mut runner = VM::default();
    let args = aurora_engine::parameters::NewCallArgs {
        chain_id: aurora_engine_types::types::u256_to_arr(&U256::from(runner.chain_id)),
        owner_id: runner.aurora_account_id.as_str().parse().unwrap(),
        bridge_prover_id: "bridge_prover.near".parse().unwrap(),
        upgrade_delay_blocks: 1,
    };

    let account_id = runner.aurora_account_id.clone();
    let (_, maybe_error) = runner.call("new", &account_id, args.try_to_vec().unwrap());

    assert!(maybe_error.is_none());

    let args = aurora_engine::parameters::InitCallArgs {
        prover_account: "prover.near".parse().unwrap(),
        eth_custodian_address: "d045f7e19B2488924B97F9c145b5E51D0D895A65".to_string(),
        metadata: FungibleTokenMetadata::default(),
    };
    let (_, maybe_error) =
        runner.call("new_eth_connector", &account_id, args.try_to_vec().unwrap());

    assert!(maybe_error.is_none());

    runner
}

fn sign_transaction(
    tx: TransactionLegacy,
    chain_id: Option<u64>,
    secret_key: &SecretKey,
) -> LegacyEthSignedTransaction {
    let mut rlp_stream = rlp::RlpStream::new();
    tx.rlp_append_unsigned(&mut rlp_stream, chain_id);
    let message_hash = aurora_engine_sdk::keccak(rlp_stream.as_raw());
    let message = secp256k1::Message::parse_slice(message_hash.as_bytes()).unwrap();

    let (signature, recovery_id) = secp256k1::sign(&message, secret_key);
    let v: u64 = match chain_id {
        Some(chain_id) => (recovery_id.serialize() as u64) + 2 * chain_id + 35,
        None => (recovery_id.serialize() as u64) + 27,
    };
    let r = U256::from_big_endian(&signature.r.b32());
    let s = U256::from_big_endian(&signature.s.b32());
    LegacyEthSignedTransaction {
        transaction: tx,
        v,
        r,
        s,
    }
}

#[derive(Default, Clone)]
pub struct ExecutionProfile {
    host_breakdown: ProfileData,
    wasm_gas: u64,
}

impl ExecutionProfile {
    fn new(outcome: &VMOutcome) -> Self {
        let wasm_gas =
            outcome.burnt_gas - outcome.profile.host_gas() - outcome.profile.action_gas();
        Self {
            host_breakdown: outcome.profile.clone(),
            wasm_gas,
        }
    }

    fn all_gas(&self) -> u64 {
        self.wasm_gas + self.host_breakdown.host_gas() + self.host_breakdown.action_gas()
    }
}
