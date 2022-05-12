use clap::Parser;

mod errors;
mod mocked_external;
mod program;
mod runtime;
mod solidity;
#[cfg(test)]
mod tests;

fn main() {
    let args = Cli::parse();

    let program = read_program(&args.script_path).unwrap();

    let finished_runtime = runtime::execute(program).unwrap();
    for string in finished_runtime.print_buffer {
        println!("{}", string);
    }
}

fn read_program(path: &str) -> Result<program::Program, std::io::Error> {
    let reader = std::fs::File::open(path)?;
    let program = serde_json::from_reader(reader)?;
    Ok(program)
}

#[derive(Parser)]
pub struct Cli {
    #[clap(short, long)]
    pub script_path: String,
}
