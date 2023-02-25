use aes_gcm::aead::{generic_array::GenericArray, Aead as _, KeyInit as _, Payload};
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use hmac::Hmac;
use rand_core::{OsRng, RngCore as _};
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

    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(encoded_password, &salt, 400_000, &mut key);

    let key = GenericArray::from_slice(&key);
    let nonce = GenericArray::from_slice(&iv);
    let payload = Payload {
        msg: encoded_plaintext,
        aad: &[],
    };
    let ciphertext = Aes256Gcm::new(key).encrypt(nonce, payload).unwrap();

    let content = [salt.as_slice(), iv.as_slice(), ciphertext.as_slice()].concat();
    let content = general_purpose::STANDARD.encode(content);

    println!("{content}");
}
