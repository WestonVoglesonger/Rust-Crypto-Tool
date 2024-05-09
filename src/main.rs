mod ops;
use ops::{hash, encrypt, decrypt};
use clap::{App, Arg, SubCommand};

fn main() {
    let matches = App::new("Rust Crypto Tool")
        .version("0.1.0")
        .author("Weston Voglesonger")
        .about("A simple CLI tool for encrypting and decrypting files.")
        .subcommand(SubCommand::with_name("hash")
                .about("Computes the hash of an input")
                .arg(Arg::with_name("INPUT")
                         .help("Input to hash")
                         .required(true)
                         .index(1)))
        .subcommand(SubCommand::with_name("encrypt")
                .about("Encrypts the input")
                .arg(Arg::with_name("INPUT")
                         .help("Input file to encrypt")
                         .required(true)
                         .index(1)))
        .subcommand(SubCommand::with_name("decrypt")
                .about("Decrypts the input")
                .arg(Arg::with_name("INPUT")
                         .help("Decrypts the input")
                         .required(true)
                         .index(1)))
        .get_matches();

        match matches.subcommand() {
            ("hash", Some(sub_m)) => {
                let input = sub_m.value_of("INPUT").unwrap();
                let hash = hash(input.as_bytes());
                println!("Hash: {}", hash);
            },
            ("encrypt", Some(sub_m)) => {
                let input = sub_m.value_of("INPUT").unwrap();
                let encrypted = encrypt(input);
                println!("Encrypted: {}", encrypted);
            },
            ("decrypt", Some(sub_m)) => {
                let input = sub_m.value_of("INPUT").unwrap();
                let decrypted = decrypt(input);
                println!("Decrypted: {}", decrypted);
            },
            _ => println!("Invalid command")
        }
}
