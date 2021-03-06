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

    let text_program = r#"
        let my_account = create_account(initial_balance=0x00)
        let my_contract = deploy_contract(
            contract=raw(0x608060405234801561001057600080fd5b50610021806100206000396000f300608060405234801561001057600080fd5b50610001806100206000396000f30000)
            signer=my_account
        )
        let my_call = call_contract(
            contract=my_contract,
            signer=my_account,
        )
        let expected_bytes = primitive(bytes(0x00))
        let actual_bytes = get_output(my_call)
        assert_eq(expected_bytes, actual_bytes)
    "#;
    let program = Program { statements };

    assert_eq!(
        program,
        crate::parser::parse_program(&text_program).unwrap()
    );
    runtime::execute(program).unwrap();
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

    let text_program = r#"
        let source = create_account(initial_balance=0xffffffff)
        let dest = primitive(bytes(0x000000000000000000beef000000000000000000))
        let transfer = call_contract(
            contract=dest,
            signer=source,
            value=0x00000fff,
        )

        let source_expected_balance = primitive(uint(0xfffff000))
        let source_actual_balance = get_balance(source)
        assert_eq(source_expected_balance, source_actual_balance)

        let source_expected_nonce = primitive(uint(0x01))
        let source_actual_nonce = get_nonce(source)
        assert_eq(source_expected_nonce, source_actual_nonce)

        let dest_expected_balance = primitive(uint(0x00000fff))
        let dest_actual_balance = get_balance(dest)
        assert_eq(dest_expected_balance, dest_actual_balance)
    "#;
    let program = Program { statements };

    assert_eq!(
        program,
        crate::parser::parse_program(&text_program).unwrap()
    );
    runtime::execute(program).unwrap();
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

#[test]
fn test_erc20() {
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
        Statement::Assign {
            name: "my_erc20".into(),
            expression: Expression::DeployContract {
                contract: DeployContractData::WithABI {
                    abi_path: "src/tests/res/ERC20PresetMinterPauser.abi".into(),
                    compiled_contract_path: "src/tests/res/ERC20PresetMinterPauser.bin".into(),
                },
                signing_account: "my_account".into(),
                constructor_args: Some(vec![
                    EthABIToken::String("TOKEN_A".into()),
                    EthABIToken::String("AAA".into()),
                ]),
                value: None,
            },
        },
        Statement::Assign {
            name: "mint_call".into(),
            expression: Expression::CallContract {
                contract: "my_erc20".into(),
                signing_account: "my_account".into(),
                data: Some(CallContractData::SolidityMethod {
                    name: "mint".into(),
                    args: Some(vec![
                        EthABIToken::Address("0xabd0b104ffbe72538503e886e367b7b15dcba1c5".into()),
                        EthABIToken::Uint("0xffffffff".into()),
                    ]),
                }),
                value: None,
            },
        },
        Statement::Assign {
            name: "transfer_call".into(),
            expression: Expression::CallContract {
                contract: "my_erc20".into(),
                signing_account: "my_account".into(),
                data: Some(CallContractData::SolidityMethod {
                    name: "transfer".into(),
                    args: Some(vec![
                        EthABIToken::Address("0x000000000000000000beef000000000000000000".into()),
                        EthABIToken::Uint("0xffff0000".into()),
                    ]),
                }),
                value: None,
            },
        },
        Statement::Assign {
            name: "owner_balance_call".into(),
            expression: Expression::CallContract {
                contract: "my_erc20".into(),
                signing_account: "my_account".into(),
                data: Some(CallContractData::SolidityMethod {
                    name: "balanceOf".into(),
                    args: Some(vec![EthABIToken::Address(
                        "0xabd0b104ffbe72538503e886e367b7b15dcba1c5".into(),
                    )]),
                }),
                value: None,
            },
        },
        Statement::Assign {
            name: "recipient_balance_call".into(),
            expression: Expression::CallContract {
                contract: "my_erc20".into(),
                signing_account: "my_account".into(),
                data: Some(CallContractData::SolidityMethod {
                    name: "balanceOf".into(),
                    args: Some(vec![EthABIToken::Address(
                        "0x000000000000000000beef000000000000000000".into(),
                    )]),
                }),
                value: None,
            },
        },
        Statement::Assign {
            name: "owner_expected_balance".into(),
            expression: Expression::Primitive(Primitive::Bytes(
                "0x000000000000000000000000000000000000000000000000000000000000ffff".into(),
            )),
        },
        Statement::Assign {
            name: "owner_actual_balance".into(),
            expression: Expression::GetOutput {
                contract_call: "owner_balance_call".into(),
            },
        },
        Statement::Assign {
            name: "recipient_expected_balance".into(),
            expression: Expression::Primitive(Primitive::Bytes(
                "0x00000000000000000000000000000000000000000000000000000000ffff0000".into(),
            )),
        },
        Statement::Assign {
            name: "recipient_actual_balance".into(),
            expression: Expression::GetOutput {
                contract_call: "recipient_balance_call".into(),
            },
        },
        Statement::AssertEq {
            left: "owner_expected_balance".into(),
            right: "owner_actual_balance".into(),
        },
        Statement::AssertEq {
            left: "recipient_expected_balance".into(),
            right: "recipient_actual_balance".into(),
        },
    ];

    let text_program = r#"
        let my_account = create_account(
            initial_balance=0x00,
            secret_key=0xbeef000000000000000000000000000000000000000000000000000000000000,
        )
        let my_erc20 = deploy_contract(
            contract=abi_bin(
                abi_path=src/tests/res/ERC20PresetMinterPauser.abi,
                bin_path=src/tests/res/ERC20PresetMinterPauser.bin,
            ),
            signer=my_account,
            constructor_args=("TOKEN_A", "AAA"),
        )
        let mint_call = call_contract(
            contract=my_erc20,
            signer=my_account,
            data=solidity(
                method=mint,
                args=(address(0xabd0b104ffbe72538503e886e367b7b15dcba1c5), uint(0xffffffff))
            )
        )
        let transfer_call = call_contract(
            contract=my_erc20,
            signer=my_account,
            data=solidity(
                method=transfer,
                args=(address(0x000000000000000000beef000000000000000000), uint(0xffff0000))
            )
        )
        let owner_balance_call = call_contract(
            contract=my_erc20,
            signer=my_account,
            data=solidity(
                method=balanceOf,
                args=(address(0xabd0b104ffbe72538503e886e367b7b15dcba1c5))
            )
        )
        let recipient_balance_call = call_contract(
            contract=my_erc20,
            signer=my_account,
            data=solidity(
                method=balanceOf,
                args=(address(0x000000000000000000beef000000000000000000))
            )
        )
        let owner_expected_balance = primitive(bytes(0x000000000000000000000000000000000000000000000000000000000000ffff))
        let owner_actual_balance = get_output(owner_balance_call)
        let recipient_expected_balance = primitive(bytes(0x00000000000000000000000000000000000000000000000000000000ffff0000))
        let recipient_actual_balance = get_output(recipient_balance_call)
        assert_eq(owner_expected_balance, owner_actual_balance)
        assert_eq(recipient_expected_balance, recipient_actual_balance)
    "#;
    let program = Program { statements };

    assert_eq!(
        program,
        crate::parser::parse_program(&text_program).unwrap()
    );
    runtime::execute(program).unwrap();
}
