// ops.rs
use ring::{digest, aead::{self, Aad, LessSafeKey, Nonce, UnboundKey}};
use arrayref::array_ref;  // Make sure this is correctly imported

pub fn hash(input: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, input);
    hex::encode(digest.as_ref())
}

pub fn encrypt(input: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)?;
    let nonce = Nonce::assume_unique_for_key(*array_ref!(nonce, 0, 12));
    let aead = LessSafeKey::new(unbound_key);
    let mut in_out = input.to_vec();
    let tag_len = aead.algorithm().tag_len();
    in_out.extend_from_slice(&vec![0u8; tag_len]);
    aead.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)?;
    println!("Encrypted + Tag: {:?}", in_out);
    Ok(in_out)
}

pub fn decrypt(input: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)?;
    let nonce = Nonce::assume_unique_for_key(*array_ref!(nonce, 0, 12));
    let aead = LessSafeKey::new(unbound_key);
    let tag_len = aead.algorithm().tag_len();
    let (enc_data, tag) = input.split_at(input.len() - tag_len);
    println!("Encrypted Data: {:?}", enc_data);
    println!("Tag: {:?}", tag);
    let mut in_out = enc_data.to_vec();
    aead.open_in_place(nonce, Aad::empty(), &mut in_out)?;
    println!("Decrypted Data: {:?}", in_out);
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SystemRandom, SecureRandom};

    #[test]
    fn test_hash() {
        let data = "Hello, world!";
        let hashed_data = hash(data.as_bytes());
        println!("Hashed data: {}", hashed_data);
        assert_ne!(hashed_data, data); // Simple check to ensure hashing changes the input
    }

    #[test]
    fn test_encrypt_decrypt() {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce).unwrap();

        let data = "Secret data";
        println!("Original data: {}", data);
        println!("Key: {:?}", key);
        println!("Nonce: {:?}", nonce);

        match encrypt(data.as_bytes(), &key, &nonce) {
            Ok(encrypted_data) => {
                println!("Encrypted data: {:?}", encrypted_data);
                println!("Encrypted data length: {}", encrypted_data.len());
                // Check that the encrypted data includes the tag
                assert!(encrypted_data.len() > data.as_bytes().len(), "Tag not appended correctly");

                match decrypt(&encrypted_data, &key, &nonce) {
                    Ok(decrypted_data) => {
                        println!("Decrypted data: {:?}", String::from_utf8_lossy(&decrypted_data));
                        assert_eq!(decrypted_data, data.as_bytes(), "Decrypted data should match the original");
                    },
                    Err(e) => {
                        println!("Decryption failed: {:?}", e);
                        panic!("Decryption failed: {:?}", e);
                    },
                }
            },
            Err(e) => {
                println!("Encryption failed: {:?}", e);
                panic!("Encryption failed: {:?}", e);
            },
        }
    }

    #[test]
    fn test_encryption_integrity() {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce).unwrap();

        let data = "Integrity test data";
        let mut encrypted_data = encrypt(data.as_bytes(), &key, &nonce).expect("Encryption failed");

        // Modify the encrypted data to simulate tampering
        encrypted_data[0] ^= 0xff;

        let decryption_attempt = decrypt(&encrypted_data, &key, &nonce);
        assert!(decryption_attempt.is_err(), "Decryption should fail when data integrity is compromised");
    }
}
