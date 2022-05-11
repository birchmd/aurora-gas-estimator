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

#[derive(Debug)]
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

    // TODO: remove unwraps
    pub fn deploy_with_args(&self, nonce: U256, args: &[ethabi::Token]) -> TransactionLegacy {
        let data = self
            .abi
            .constructor()
            .unwrap()
            .encode_input(self.code.clone(), args)
            .unwrap();
        TransactionLegacy {
            nonce,
            gas_price: Default::default(),
            gas_limit: u64::MAX.into(),
            to: None,
            value: Default::default(),
            data,
        }
    }
}

impl DeployedContract {
    pub fn call_method_without_args(&self, method_name: &str, nonce: U256) -> TransactionLegacy {
        self.call_method_with_args(method_name, &[], nonce)
    }

    // TODO: remove unwraps
    pub fn call_method_with_args(
        &self,
        method_name: &str,
        args: &[ethabi::Token],
        nonce: U256,
    ) -> TransactionLegacy {
        let data = self
            .abi
            .function(method_name)
            .unwrap()
            .encode_input(args)
            .unwrap();
        TransactionLegacy {
            nonce,
            gas_price: Default::default(),
            gas_limit: u64::MAX.into(),
            to: Some(self.address),
            value: Default::default(),
            data,
        }
    }
}
