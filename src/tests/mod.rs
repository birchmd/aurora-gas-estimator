use crate::program::*;
use crate::runtime;

#[test]
fn test_deploy_contract() {
    let statements = vec![
        Statement::Assign {
            name: "my_account".into(),
            expression: Expression::CreateAccount {
                initial_balance: "0x00".into(),
                secret_key: None,
                initial_nonce: None,
            },
        },
        Statement::Assign {
            name: "my_contract".into(),
            expression: Expression::DeployContract {
                contract: DeployContractData::Raw {
                    evm_bytes:
                        "0x608060405234801561001057600080fd5b50610001806100206000396000f30000"
                            .into(),
                },
                signing_account: "my_account".into(),
                constructor_args: None,
                value: None,
            },
        },
    ];

    runtime::execute(Program { statements }).unwrap();
}
