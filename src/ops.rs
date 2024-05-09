use ring::digest::{Context, SHA256};

pub fn hash(input: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(input);
    let digest = context.finish();
    let hash = digest.as_ref();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn encrypt(input: &str) -> String {
    input.to_string()
}

pub fn decrypt(input: &str) -> String {
    input.to_string()
}