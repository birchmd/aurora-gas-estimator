//! This module contains data structures that describe the programs the estimator can execute.

use crate::errors;
use aurora_engine_types::{H160, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Program {
    pub statements: Vec<Statement>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Statement {
    Assign {
        name: Variable,
        expression: Expression,
    },
    AssertEq {
        left: Variable,
        right: Variable,
    },
    Print {
        value: Variable,
    },
}

// Expression to pull data from live network maybe? (eg replay deploy txs, download contract data)

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Expression {
    CreateAccount {
        initial_balance: HexString,
        secret_key: Option<HexString>,
        initial_nonce: Option<u64>,
    },
    DeployContract {
        contract: DeployContractData,
        signing_account: Variable,
        constructor_args: Option<Vec<EthABIToken>>,
        value: Option<HexString>,
    },
    CallContract {
        contract: Variable,
        signing_account: Variable,
        data: Option<CallContractData>,
        value: Option<HexString>,
    },
    GetBalance {
        address: Variable,
    },
    GetNonce {
        address: Variable,
    },
    GetCode {
        address: Variable,
    },
    GetOutput {
        contract_call: Variable,
    },
    Primitive(Primitive),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Primitive {
    Variable(Variable),
    U256(HexString),
    Bytes(HexString),
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Variable(pub String);

impl From<&str> for Variable {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexString(pub String);

impl HexString {
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        let without_prefix = self.0.strip_prefix("0x").unwrap_or(&self.0);
        hex::decode(without_prefix)
    }
}

impl From<&str> for HexString {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EthABIToken {
    Address(HexString),
    FixedBytes(HexString),
    Bytes(HexString),
    Int(i128),
    Uint(HexString),
    Bool(bool),
    String(String),
    Array(Vec<EthABIToken>),
    Tuple(Vec<EthABIToken>),
}

impl TryFrom<EthABIToken> for ethabi::Token {
    type Error = errors::TokenParseError;

    fn try_from(value: EthABIToken) -> Result<Self, Self::Error> {
        match value {
            EthABIToken::Address(addr_hex) => {
                let bytes = addr_hex.try_to_bytes()?;

                if bytes.len() != 20 {
                    return Err(errors::TokenParseError::InvalidAddress);
                }

                Ok(ethabi::Token::Address(H160::from_slice(&bytes)))
            }
            EthABIToken::FixedBytes(bytes_hex) => {
                let bytes = bytes_hex.try_to_bytes()?;
                Ok(ethabi::Token::FixedBytes(bytes))
            }
            EthABIToken::Bytes(bytes_hex) => {
                let bytes = bytes_hex.try_to_bytes()?;
                Ok(ethabi::Token::Bytes(bytes))
            }
            EthABIToken::Int(i) => Ok(ethabi::Token::Int(i.into())),
            EthABIToken::Uint(number_hex) => {
                let bytes = number_hex.try_to_bytes()?;
                Ok(ethabi::Token::Uint(U256::from_big_endian(&bytes)))
            }
            EthABIToken::Bool(b) => Ok(ethabi::Token::Bool(b)),
            EthABIToken::String(s) => Ok(ethabi::Token::String(s)),
            EthABIToken::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());

                arr.into_iter()
                    .try_for_each(|token| token.try_into().map(|t| result.push(t)))?;

                Ok(ethabi::Token::Array(result))
            }
            EthABIToken::Tuple(tup) => {
                let mut result = Vec::with_capacity(tup.len());

                tup.into_iter()
                    .try_for_each(|token| token.try_into().map(|t| result.push(t)))?;

                Ok(ethabi::Token::Tuple(result))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeployContractData {
    ExtJson {
        extended_json_path: String,
    },
    WithABI {
        abi_path: String,
        compiled_contract_path: String,
    },
    Raw {
        evm_bytes: HexString,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallContractData {
    Raw(HexString),
    SolidityMethod {
        name: String,
        args: Option<Vec<EthABIToken>>,
    },
}
