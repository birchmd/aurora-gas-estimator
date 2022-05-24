use clap::Parser;

mod errors;
mod mocked_external;
mod parser;
mod program;
mod runtime;
mod solidity;
#[cfg(test)]
mod tests;

fn main() {
    let args = Cli::parse();

    let program = if args.json_format {
        read_json_program(&args.script_path).unwrap()
    } else {
        read_program(&args.script_path).unwrap()
    };

    let finished_runtime = runtime::execute(program).unwrap();
    let output = Output {
        output: finished_runtime.print_buffer,
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn read_json_program(path: &str) -> Result<program::Program, std::io::Error> {
    let reader = std::fs::File::open(path)?;
    let program = serde_json::from_reader(reader)?;
    Ok(program)
}

fn read_program(path: &str) -> Result<program::Program, std::io::Error> {
    let text = std::fs::read_to_string(path)?;
    let program = parser::parse_program(&text).unwrap();
    Ok(program)
}

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    script_path: String,
    #[clap(short, long)]
    json_format: bool,
}

#[derive(serde::Serialize)]
struct Output {
    output: Vec<serde_json::Value>,
}
