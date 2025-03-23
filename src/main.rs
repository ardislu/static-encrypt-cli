use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload, generic_array::GenericArray};
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use hmac::Hmac;
use rand_core::{OsRng, TryRngCore};
use sha2::Sha512;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The static content to encrypt.
    plaintext: String,

    /// The password to decrypt the content.
    password: String,
}

fn main() {
    let cli = Cli::parse();
    let encoded_plaintext = cli.plaintext.as_bytes();
    let encoded_password = cli.password.as_bytes();
    let additional_data = "https://github.com/ardislu/static-encrypt".as_bytes();

    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut salt).ok();
    OsRng.try_fill_bytes(&mut iv).ok();

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(encoded_password, &salt, 400_000, &mut key).unwrap();

    let key = GenericArray::from_slice(&key);
    let nonce = GenericArray::from_slice(&iv);
    let payload = Payload {
        msg: encoded_plaintext,
        aad: additional_data,
    };
    let ciphertext = Aes256Gcm::new(key).encrypt(nonce, payload).unwrap();

    let content = [salt.as_slice(), iv.as_slice(), ciphertext.as_slice()].concat();
    let content = general_purpose::STANDARD.encode(content);

    println!("{content}");
}
