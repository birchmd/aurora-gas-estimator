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

#[test]
fn test_call_contract() {
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
                        "0x608060405234801561001057600080fd5b50610021806100206000396000f300608060405234801561001057600080fd5b50610001806100206000396000f30000"
                            .into(),
                },
                signing_account: "my_account".into(),
                constructor_args: None,
                value: None,
            },
        },
        Statement::Assign {
            name: "my_call".into(),
            expression: Expression::CallContract { contract: "my_contract".into(), signing_account: "my_account".into(), data: None, value: None }
        },
        Statement::Assign {
            name: "expected_bytes".into(),
            expression: Expression::Primitive(Primitive::Bytes("0x00".into())),
        },
        Statement::Assign {
            name: "actual_bytes".into(),
            expression: Expression::GetOutput {
                contract_call: "my_call".into(),
            },
        },
        Statement::AssertEq {
            left: "expected_bytes".into(),
            right: "actual_bytes".into(),
        },
    ];

    runtime::execute(Program { statements }).unwrap();
}

#[test]
fn test_eth_transfer() {
    let statements = vec![
        Statement::Assign {
            name: "source".into(),
            expression: Expression::CreateAccount {
                initial_balance: "0xffffffff".into(),
                secret_key: None,
                initial_nonce: None,
            },
        },
        Statement::Assign {
            name: "dest".into(),
            expression: Expression::Primitive(Primitive::Bytes(
                "0x000000000000000000beef000000000000000000".into(),
            )),
        },
        Statement::Assign {
            name: "transfer".into(),
            expression: Expression::CallContract {
                contract: "dest".into(),
                signing_account: "source".into(),
                data: None,
                value: Some("0x00000fff".into()),
            },
        },
        Statement::Assign {
            name: "source_expected_balance".into(),
            expression: Expression::Primitive(Primitive::U256("0xfffff000".into())),
        },
        Statement::Assign {
            name: "source_actual_balance".into(),
            expression: Expression::GetBalance {
                address: "source".into(),
            },
        },
        Statement::AssertEq {
            left: "source_expected_balance".into(),
            right: "source_actual_balance".into(),
        },
        Statement::Assign {
            name: "source_expected_nonce".into(),
            expression: Expression::Primitive(Primitive::U256("0x01".into())),
        },
        Statement::Assign {
            name: "source_actual_nonce".into(),
            expression: Expression::GetNonce {
                address: "source".into(),
            },
        },
        Statement::AssertEq {
            left: "source_expected_nonce".into(),
            right: "source_actual_nonce".into(),
        },
        Statement::Assign {
            name: "dest_expected_balance".into(),
            expression: Expression::Primitive(Primitive::U256("0x00000fff".into())),
        },
        Statement::Assign {
            name: "dest_actual_balance".into(),
            expression: Expression::GetBalance {
                address: "dest".into(),
            },
        },
        Statement::AssertEq {
            left: "dest_expected_balance".into(),
            right: "dest_actual_balance".into(),
        },
    ];

    runtime::execute(Program { statements }).unwrap();
}

#[test]
fn test_print() {
    let statements = vec![
        Statement::Assign {
            name: "my_account".into(),
            expression: Expression::CreateAccount {
                initial_balance: "0x00".into(),
                secret_key: Some(
                    "0xbeef000000000000000000000000000000000000000000000000000000000000".into(),
                ),
                initial_nonce: None,
            },
        },
        Statement::Print {
            value: "my_account".into(),
        },
    ];

    let finished_runtime = runtime::execute(Program { statements }).unwrap();
    let printed_string =
        serde_json::to_string_pretty(finished_runtime.print_buffer.first().unwrap()).unwrap();
    let expected_string = r#"
        {
            "SigningAccount": {
                "address": "0xabd0b104ffbe72538503e886e367b7b15dcba1c5"
            }
        }
    "#;
    assert_eq!(
        printed_string.replace(" ", "").trim(),
        expected_string.replace(" ", "").trim()
    )
}
