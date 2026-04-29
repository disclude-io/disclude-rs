use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match disclude::run_cli(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("disclude: {:#}", e);
            ExitCode::from(2_u8)
        }
    }
}
