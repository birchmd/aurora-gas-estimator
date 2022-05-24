//! Functions to parse the "language" used to specify scripts defining EVM workflows.

use crate::program;

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, alphanumeric1, hex_digit1, multispace0, multispace1, none_of},
    combinator::{all_consuming, map, map_res, recognize},
    multi::{many0_count, many1, many_m_n, separated_list0},
    sequence::{delimited, pair, terminated, tuple},
    IResult, Parser,
};

pub type ParseError<'a> = nom::Err<nom::error::Error<&'a str>>;

pub fn parse_program(input: &str) -> Result<program::Program, ParseError> {
    let (_, statements) =
        all_consuming(many1(delimited(multispace0, parse_statement, multispace0)))(input)?;

    Ok(program::Program { statements })
}

fn parse_statement(input: &str) -> IResult<&str, program::Statement> {
    alt((parse_assign, parse_assert_eq, parse_print))(input)
}

fn parse_assign(input: &str) -> IResult<&str, program::Statement> {
    let result = tuple((
        tag("let"),
        multispace1,
        parse_variable,
        multispace0,
        tag("="),
        multispace0,
        parse_expression,
    ))(input);
    result.map(|(i, (_, _, v, _, _, _, e))| {
        (
            i,
            program::Statement::Assign {
                name: v,
                expression: e,
            },
        )
    })
}

fn parse_assert_eq(input: &str) -> IResult<&str, program::Statement> {
    let result = tuple((
        tag("assert_eq("),
        multispace0,
        parse_variable,
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_variable,
        multispace0,
        parse_optional(tag(",")),
        tag(")"),
    ))(input);

    result.map(|(i, (_, _, left, _, _, _, right, _, _, _))| {
        (i, program::Statement::AssertEq { left, right })
    })
}

fn parse_print(input: &str) -> IResult<&str, program::Statement> {
    let result = delimited(tag("print("), parse_variable, tag(")"))(input);

    result.map(|(i, v)| (i, program::Statement::Print { value: v }))
}

fn parse_variable(input: &str) -> IResult<&str, program::Variable> {
    let result = recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))(input);
    result.map(|(i, v)| (i, v.into()))
}

fn parse_hex(input: &str) -> IResult<&str, program::HexString> {
    let result = tuple((parse_optional(tag("0x")), hex_digit1))(input);
    result.map(|(i, (maybe_0x, hex_str))| {
        let mut result = String::with_capacity(2 + hex_str.len());
        if let Some(prefix) = maybe_0x {
            result.push_str(prefix);
        }
        result.push_str(hex_str);
        (i, program::HexString(result))
    })
}

fn parse_expression(input: &str) -> IResult<&str, program::Expression> {
    alt((
        parse_create_account,
        parse_deploy_contract,
        parse_call_contract,
        parse_get_balance,
        parse_get_nonce,
        parse_get_code,
        parse_get_output,
        parse_primitive_expression,
    ))(input)
}

fn parse_get_balance(input: &str) -> IResult<&str, program::Expression> {
    let result = delimited(tag("get_balance("), parse_variable, tag(")"))(input);
    result.map(|(i, v)| (i, program::Expression::GetBalance { address: v }))
}

fn parse_get_nonce(input: &str) -> IResult<&str, program::Expression> {
    let result = delimited(tag("get_nonce("), parse_variable, tag(")"))(input);
    result.map(|(i, v)| (i, program::Expression::GetNonce { address: v }))
}

fn parse_get_code(input: &str) -> IResult<&str, program::Expression> {
    let result = delimited(tag("get_code("), parse_variable, tag(")"))(input);
    result.map(|(i, v)| (i, program::Expression::GetCode { address: v }))
}

fn parse_get_output(input: &str) -> IResult<&str, program::Expression> {
    let result = delimited(tag("get_output("), parse_variable, tag(")"))(input);
    result.map(|(i, v)| (i, program::Expression::GetOutput { contract_call: v }))
}

fn parse_primitive_expression(input: &str) -> IResult<&str, program::Expression> {
    let result = delimited(tag("primitive("), parse_primitive, tag(")"))(input);
    result.map(|(i, v)| (i, program::Expression::Primitive(v)))
}

fn parse_primitive(input: &str) -> IResult<&str, program::Primitive> {
    let (remainder, name) = alt((
        tag("var"),
        tag("uint"),
        tag("bytes"),
        tag("true"),
        tag("false"),
        tag(r#"""#),
    ))(input)?;

    match name {
        "var" => {
            let args = delimited(tag("("), parse_variable, tag(")"))(remainder);
            args.map(|(i, v)| (i, program::Primitive::Variable(v)))
        }
        "uint" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, v)| (i, program::Primitive::U256(v)))
        }
        "bytes" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, v)| (i, program::Primitive::Bytes(v)))
        }
        "true" => Ok((remainder, program::Primitive::Bool(true))),
        "false" => Ok((remainder, program::Primitive::Bool(true))),
        r#"""# => {
            let args = terminated(many1(none_of(r#"""#)), tag(r#"""#))(remainder);
            args.map(|(i, v)| (i, program::Primitive::String(String::from_iter(v))))
        }
        _ => unreachable!(),
    }
}

fn parse_call_contract(input: &str) -> IResult<&str, program::Expression> {
    let result = tuple((
        tag("call_contract("),
        multispace0,
        parse_kv_pair("contract", parse_variable),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_kv_pair("signer", parse_variable),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair("data", parse_call_contract_data)),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair("value", parse_hex)),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        tag(")"),
    ))(input);
    result.map(
        |(i, (_, _, c, _, _, _, s, _, _, _, d, _, _, _, v, _, _, _, _))| {
            (
                i,
                program::Expression::CallContract {
                    contract: c,
                    signing_account: s,
                    data: d,
                    value: v,
                },
            )
        },
    )
}

fn parse_call_contract_data(input: &str) -> IResult<&str, program::CallContractData> {
    let (remainder, name) = alt((tag("raw"), tag("solidity")))(input)?;

    match name {
        "raw" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, bytes)| (i, program::CallContractData::Raw(bytes)))
        }
        "solidity" => {
            let args = tuple((
                tag("("),
                multispace0,
                parse_kv_pair("method", map(parse_variable, |v| v.0)),
                multispace0,
                parse_optional(tag(",")),
                multispace0,
                parse_optional(parse_kv_pair(
                    "args",
                    delimited(
                        tag("("),
                        separated_list0(
                            tuple((multispace0, tag(","), multispace0)),
                            parse_eth_abi_token,
                        ),
                        tag(")"),
                    ),
                )),
                multispace0,
                parse_optional(tag(",")),
                multispace0,
                tag(")"),
            ))(remainder);
            args.map(|(i, (_, _, method, _, _, _, args, _, _, _, _))| {
                (
                    i,
                    program::CallContractData::SolidityMethod { name: method, args },
                )
            })
        }
        _ => unreachable!(),
    }
}

fn parse_deploy_contract(input: &str) -> IResult<&str, program::Expression> {
    let result = tuple((
        tag("deploy_contract("),
        multispace0,
        parse_kv_pair("contract", parse_deploy_contract_data),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_kv_pair("signer", parse_variable),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair(
            "constructor_args",
            delimited(
                tag("("),
                separated_list0(
                    tuple((multispace0, tag(","), multispace0)),
                    parse_eth_abi_token,
                ),
                tag(")"),
            ),
        )),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair("value", parse_hex)),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        tag(")"),
    ))(input);
    result.map(
        |(i, (_, _, c, _, _, _, s, _, _, _, a, _, _, _, v, _, _, _, _))| {
            (
                i,
                program::Expression::DeployContract {
                    contract: c,
                    signing_account: s,
                    constructor_args: a,
                    value: v,
                },
            )
        },
    )
}

fn parse_eth_abi_token(input: &str) -> IResult<&str, program::EthABIToken> {
    let (remainder, name) = alt((
        tag("address"),
        tag("fixed"),
        tag("bytes"),
        tag("int"),
        tag("uint"),
        tag("true"),
        tag("false"),
        tag(r#"""#),
        tag("array"),
        tag("tuple"),
    ))(input)?;

    match name {
        "address" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, bytes)| (i, program::EthABIToken::Address(bytes)))
        }
        "fixed" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, bytes)| (i, program::EthABIToken::FixedBytes(bytes)))
        }
        "bytes" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, bytes)| (i, program::EthABIToken::Bytes(bytes)))
        }
        "int" => {
            todo!()
        }
        "uint" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, bytes)| (i, program::EthABIToken::Uint(bytes)))
        }
        "true" => Ok((remainder, program::EthABIToken::Bool(true))),
        "false" => Ok((remainder, program::EthABIToken::Bool(false))),
        r#"""# => {
            let args = terminated(many1(none_of(r#"""#)), tag(r#"""#))(remainder);
            args.map(|(i, chrs)| (i, program::EthABIToken::String(String::from_iter(chrs))))
        }
        "array" => {
            let args = separated_list0(
                tuple((multispace0, tag(","), multispace0)),
                parse_eth_abi_token,
            )(remainder);
            args.map(|(i, tokens)| (i, program::EthABIToken::Array(tokens)))
        }
        "tuple" => {
            let args = separated_list0(
                tuple((multispace0, tag(","), multispace0)),
                parse_eth_abi_token,
            )(remainder);
            args.map(|(i, tokens)| (i, program::EthABIToken::Tuple(tokens)))
        }
        _ => unreachable!(),
    }
}

fn parse_deploy_contract_data(input: &str) -> IResult<&str, program::DeployContractData> {
    let (remainder, name) = alt((tag("ext_json"), tag("abi_bin"), tag("raw")))(input)?;
    match name {
        "ext_json" => {
            let args = delimited(tag("("), many1(none_of("(,)")), tag(")"))(remainder);
            args.map(|(i, path)| {
                (
                    i,
                    program::DeployContractData::ExtJson {
                        extended_json_path: String::from_iter(path),
                    },
                )
            })
        }
        "abi_bin" => {
            let args = tuple((
                tag("("),
                multispace0,
                parse_kv_pair("abi_path", many1(none_of("(,)"))),
                multispace0,
                parse_optional(tag(",")),
                multispace0,
                parse_kv_pair("bin_path", many1(none_of("(,)"))),
                multispace0,
                parse_optional(tag(",")),
                multispace0,
                tag(")"),
            ))(remainder);
            args.map(|(i, (_, _, abi_path, _, _, _, bin_path, _, _, _, _))| {
                (
                    i,
                    program::DeployContractData::WithABI {
                        abi_path: String::from_iter(abi_path),
                        compiled_contract_path: String::from_iter(bin_path),
                    },
                )
            })
        }
        "raw" => {
            let args = delimited(tag("("), parse_hex, tag(")"))(remainder);
            args.map(|(i, evm_bytes)| (i, program::DeployContractData::Raw { evm_bytes }))
        }
        _ => unreachable!(),
    }
}

fn parse_create_account(input: &str) -> IResult<&str, program::Expression> {
    let result = tuple((
        tag("create_account("),
        multispace0,
        parse_kv_pair("initial_balance", parse_hex),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair("secret_key", parse_hex)),
        multispace0,
        parse_optional(tag(",")),
        multispace0,
        parse_optional(parse_kv_pair(
            "initial_nonce",
            map_res(parse_hex, |h| u64::from_str_radix(&h.0, 16)),
        )),
        multispace0,
        parse_optional(tag(",")),
        tag(")"),
    ))(input);
    result.map(|(i, (_, _, v, _, _, _, sk, _, _, _, n, _, _, _))| {
        (
            i,
            program::Expression::CreateAccount {
                initial_balance: v,
                secret_key: sk,
                initial_nonce: n,
            },
        )
    })
}

fn parse_kv_pair<'a, T, E: nom::error::ParseError<&'a str>, P: Parser<&'a str, T, E>>(
    k: &'static str,
    p: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, T, E> {
    map(tuple((tag(k), tag("="), p)), |(_, _, v)| v)
}

fn parse_optional<'a, T, E: nom::error::ParseError<&'a str>, P: Parser<&'a str, T, E>>(
    p: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, Option<T>, E> {
    map(many_m_n(0, 1, p), |mut v| v.pop())
}
