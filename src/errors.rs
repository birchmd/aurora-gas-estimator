use aurora_engine::parameters::TransactionStatus;
use near_vm_runner::VMError;

use crate::program::Variable;
use crate::runtime::{Value, ValueType};

#[derive(Debug)]
pub enum TokenParseError {
    InvalidHex(hex::FromHexError),
    InvalidAddress,
}

#[derive(Debug)]
pub enum ContractParseError {
    InvalidHex(hex::FromHexError),
    IO(std::io::Error),
    EthABI(ethabi::Error),
    Deserialize(serde_json::Error),
}

#[derive(Debug)]
pub enum RuntimeError {
    TokenParse(TokenParseError),
    Secp256k1(secp256k1::Error),
    UnknownVariable(Variable),
    TypeMismatch {
        expected: ValueType,
        received: ValueType,
    },
    ContractParseError(ContractParseError),
    VMError(VMError),
    EVMExecutionFailed(TransactionStatus),
    AssertEqFailed {
        left: Box<Value>,
        right: Box<Value>,
    },
}

impl From<hex::FromHexError> for TokenParseError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidHex(e)
    }
}

impl From<hex::FromHexError> for ContractParseError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidHex(e)
    }
}

impl From<std::io::Error> for ContractParseError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<ethabi::Error> for ContractParseError {
    fn from(e: ethabi::Error) -> Self {
        Self::EthABI(e)
    }
}

impl From<serde_json::Error> for ContractParseError {
    fn from(e: serde_json::Error) -> Self {
        Self::Deserialize(e)
    }
}

impl From<hex::FromHexError> for RuntimeError {
    fn from(e: hex::FromHexError) -> Self {
        Self::TokenParse(TokenParseError::InvalidHex(e))
    }
}

impl From<TokenParseError> for RuntimeError {
    fn from(e: TokenParseError) -> Self {
        Self::TokenParse(e)
    }
}

impl From<ContractParseError> for RuntimeError {
    fn from(e: ContractParseError) -> Self {
        Self::ContractParseError(e)
    }
}

impl From<VMError> for RuntimeError {
    fn from(e: VMError) -> Self {
        Self::VMError(e)
    }
}

impl From<secp256k1::Error> for RuntimeError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}
