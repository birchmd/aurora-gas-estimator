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
        Statement::Assign {
            name: "expected_bytes".into(),
            expression: Expression::Primitive(Primitive::Bytes("0x00".into())),
        },
        Statement::Assign {
            name: "actual_bytes".into(),
            expression: Expression::GetCode {
                address: "my_contract".into(),
            },
        },
        Statement::AssertEq {
            left: "expected_bytes".into(),
            right: "actual_bytes".into(),
        },
    ];

    runtime::execute(Program { statements }).unwrap();
}
