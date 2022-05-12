use crate::errors;
use aurora_engine_transactions::legacy::TransactionLegacy;
use aurora_engine_types::types::Address;
use aurora_engine_types::U256;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug)]
pub struct ContractConstructor {
    pub abi: ethabi::Contract,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeployedContract {
    pub abi: ethabi::Contract,
    pub address: Address,
}

#[derive(Deserialize)]
struct ExtendedJsonSolidityArtifact {
    abi: ethabi::Contract,
    bytecode: String,
}

impl ContractConstructor {
    pub fn from_abi_and_bin<P1, P2>(
        abi_path: P1,
        bin_path: P2,
    ) -> Result<Self, errors::ContractParseError>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let hex_rep = std::fs::read_to_string(bin_path)?;
        let code = hex::decode(&hex_rep)?;
        let reader = std::fs::File::open(abi_path)?;
        let abi = ethabi::Contract::load(reader)?;

        Ok(Self { abi, code })
    }

    pub fn from_extended_json<P>(contract_path: P) -> Result<Self, errors::ContractParseError>
    where
        P: AsRef<Path>,
    {
        let reader = std::fs::File::open(contract_path)?;
        let contract: ExtendedJsonSolidityArtifact = serde_json::from_reader(reader)?;

        Ok(Self {
            abi: contract.abi,
            code: hex::decode(&contract.bytecode[2..])?,
        })
    }

    pub fn deployed_at(&self, address: Address) -> DeployedContract {
        DeployedContract {
            abi: self.abi.clone(),
            address,
        }
    }

    pub fn deploy_without_constructor(&self, nonce: U256) -> TransactionLegacy {
        TransactionLegacy {
            nonce,
            gas_price: Default::default(),
            gas_limit: u64::MAX.into(),
            to: None,
            value: Default::default(),
            data: self.code.clone(),
        }
    }

    pub fn deploy_with_args(
        &self,
        nonce: U256,
        args: &[ethabi::Token],
    ) -> ethabi::Result<TransactionLegacy> {
        let data = self
            .abi
            .constructor()
            .ok_or_else(|| ethabi::Error::Other(MissingConstructor.into()))?
            .encode_input(self.code.clone(), args)?;
        Ok(TransactionLegacy {
            nonce,
            gas_price: Default::default(),
            gas_limit: u64::MAX.into(),
            to: None,
            value: Default::default(),
            data,
        })
    }
}

impl DeployedContract {
    pub fn call_method_without_args(
        &self,
        method_name: &str,
        nonce: U256,
    ) -> ethabi::Result<TransactionLegacy> {
        self.call_method_with_args(method_name, &[], nonce)
    }

    pub fn call_method_with_args(
        &self,
        method_name: &str,
        args: &[ethabi::Token],
        nonce: U256,
    ) -> ethabi::Result<TransactionLegacy> {
        let data = self.abi.function(method_name)?.encode_input(args)?;
        Ok(TransactionLegacy {
            nonce,
            gas_price: Default::default(),
            gas_limit: u64::MAX.into(),
            to: Some(self.address),
            value: Default::default(),
            data,
        })
    }
}

#[derive(Debug)]
struct MissingConstructor;

impl std::fmt::Display for MissingConstructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Missing constructor")
    }
}

impl std::error::Error for MissingConstructor {}
