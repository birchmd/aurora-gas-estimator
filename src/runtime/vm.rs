use crate::{errors, mocked_external};
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

const EVM_WASM_BYTES: &[u8; 1024938] = include_bytes!("../../aurora-engine/mainnet-release.wasm");
const AURORA_ACCOUNT_ID: &str = "aurora";

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
        let mut wasm_config = runtime_config.wasm_config.clone();
        wasm_config.limit_config.max_gas_burnt = u64::MAX;

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

        let (maybe_outcome, maybe_error) = match near_vm_runner::run(
            &self.code,
            method_name,
            &mut self.ext,
            self.context.clone(),
            &self.wasm_config,
            &self.fees_config,
            &[],
            self.current_protocol_version,
            Some(&self.cache),
        ) {
            near_vm_runner::VMResult::Aborted(outcome, error) => (Some(outcome), Some(error)),
            near_vm_runner::VMResult::Ok(outcome) => (Some(outcome), None),
        };
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

        match near_vm_runner::run(
            &self.code,
            method_name,
            &mut ext,
            context,
            &self.wasm_config,
            &self.fees_config,
            &[],
            self.current_protocol_version,
            Some(&self.cache),
        ) {
            near_vm_runner::VMResult::Aborted(outcome, error) => (Some(outcome), Some(error)),
            near_vm_runner::VMResult::Ok(outcome) => (Some(outcome), None),
        }
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

pub fn deploy_evm() -> VM {
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

#[derive(Default, Clone)]
pub struct ExecutionProfile {
    host_breakdown: ProfileData,
    wasm_gas: u64,
}

impl ExecutionProfile {
    pub fn new(outcome: &VMOutcome) -> Self {
        let wasm_gas =
            outcome.burnt_gas - outcome.profile.host_gas() - outcome.profile.action_gas();
        Self {
            host_breakdown: outcome.profile.clone(),
            wasm_gas,
        }
    }

    pub fn all_gas(&self) -> u64 {
        self.wasm_gas + self.host_breakdown.host_gas() + self.host_breakdown.action_gas()
    }
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
