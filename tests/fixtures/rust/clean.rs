// Fixture: ordinary Rust module with nothing obfuscation-worthy.
pub fn add(a: i64, b: i64) -> i64 {
    a + b
}

pub fn greet(name: &str) -> String {
    format!("hello, {}", name)
}
