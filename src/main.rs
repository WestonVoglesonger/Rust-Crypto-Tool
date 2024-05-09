mod ops;
use clap::{App, Arg, SubCommand};
use ops::{hash, encrypt, decrypt};
use ring::rand::{SystemRandom, SecureRandom};

fn main() {
    let matches = App::new("Rust Crypto Tool")
        .version("0.1.0")
        .author("Weston Vogelsonger")
        .about("Performs cryptographic operations")
        .subcommand(SubCommand::with_name("hash")
                    .about("Computes the hash of an input")
                    .arg(Arg::with_name("INPUT")
                         .help("Input to hash")
                         .required(true)
                         .index(1)))
        .subcommand(SubCommand::with_name("encrypt")
                    .about("Encrypts the input")
                    .arg(Arg::with_name("INPUT")
                         .help("Input to encrypt")
                         .required(true)
                         .index(1)))
        .subcommand(SubCommand::with_name("decrypt")
                    .about("Decrypts the input")
                    .arg(Arg::with_name("INPUT")
                         .help("Input to decrypt")
                         .required(true)
                         .index(1)))
        .get_matches();

    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).unwrap();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).unwrap();

    match matches.subcommand() {
        ("hash", Some(sub_m)) => {
            let input = sub_m.value_of("INPUT").unwrap();
            let hash_result = hash(input.as_bytes());
            println!("Hash: {}", hash_result);
        },
        ("encrypt", Some(sub_m)) => {
            let input = sub_m.value_of("INPUT").unwrap();
            match encrypt(input.as_bytes(), &key, &nonce) {
                Ok(encrypted) => println!("Encrypted: {:?}", encrypted),
                Err(e) => println!("Encryption failed: {:?}", e),
            }
        },
        ("decrypt", Some(sub_m)) => {
            let input = sub_m.value_of("INPUT").unwrap();
            match hex::decode(input) {
                Ok(decoded_input) => match decrypt(&decoded_input, &key, &nonce) {
                    Ok(decrypted) => println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap()),
                    Err(e) => println!("Decryption failed: {:?}", e),
                },
                Err(e) => println!("Decoding failed: {:?}", e),
            }
        },
        _ => println!("Invalid command or no command entered"),
    }
}
