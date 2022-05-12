use crate::program::HexString;
use crate::runtime::Signer;
use crate::solidity;
use aurora_engine::parameters::SubmitResult;
use aurora_engine_types::U256;

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
