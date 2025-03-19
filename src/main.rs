
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

use rand::RngCore;
use rand::rngs::OsRng;

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as AesNonce};

use chacha20poly1305::{Key as XKey, XChaCha20Poly1305, XNonce};

use zeroize::Zeroize;
use anyhow::{anyhow, Context, Result};

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Encrypt the file (conflicts with --D)
    #[arg(long = "E", short = 'E', conflicts_with = "decrypt")]
    encrypt: bool,

    /// Decrypt the file (conflicts with --E)
    #[arg(long = "D", short = 'D', conflicts_with = "encrypt")]
    decrypt: bool,

    /// The file to encrypt or decrypt
    #[arg(required = true)]
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Figure out if we are encrypting or decrypting
    let do_encrypt = args.encrypt;
    let do_decrypt = args.decrypt;

    if !do_encrypt && !do_decrypt {
        eprintln!("Either --E or --D is required. See --help.");
        std::process::exit(1);
    }

    let file_path = args.file;

    // Load keys
    let aes_key = fs::read("a.key").context("Failed to read a.key")?;
    let xcha_key = fs::read("x.key").context("Failed to read x.key")?;

    if aes_key.len() != 32 {
        return Err(anyhow!("a.key must be exactly 32 bytes."));
    }
    if xcha_key.len() != 32 {
        return Err(anyhow!("x.key must be exactly 32 bytes."));
    }

    let aes_key_array: &[u8; 32] = aes_key[..32].try_into().unwrap();
    let xcha_key_array: &[u8; 32] = xcha_key[..32].try_into().unwrap();

    // Read entire file into memory
    let mut file_data = fs::read(&file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

    if do_encrypt {
        let encrypted_data =
            encrypt_double(&mut file_data, aes_key_array, xcha_key_array)
                .context("Encryption failed")?;

        // file_data is now zeroized from inside the function

        // Write encrypted content to a temporary file, then rename over original
        let tmp_path = file_path.with_extension("tmp");
        {
            let mut tmp_file = fs::File::create(&tmp_path)
                .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
            tmp_file.write_all(&encrypted_data)?;
            tmp_file.sync_all()?;
        }

        fs::rename(&tmp_path, &file_path)
            .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), file_path.display()))?;

        println!("File encrypted successfully.");

    } else {
        // do_decrypt
        let decrypted_data =
            decrypt_double(&mut file_data, aes_key_array, xcha_key_array)
                .context("Decryption failed")?;

        // file_data is now zeroized inside the function

        // Write decrypted content to a temporary file, then rename over original
        let tmp_path = file_path.with_extension("tmp");
        {
            let mut tmp_file = fs::File::create(&tmp_path)
                .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
            tmp_file.write_all(&decrypted_data)?;
            tmp_file.sync_all()?;
        }

        fs::rename(&tmp_path, &file_path)
            .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), file_path.display()))?;

        println!("File decrypted successfully.");
    }

    Ok(())
}

/// Encrypt in two stages:
/// 1) AES-256-GCM-SIV
/// 2) XChaCha20-Poly1305
fn encrypt_double(data: &mut [u8], aes_key: &[u8; 32], xcha_key: &[u8; 32]) -> Result<Vec<u8>> {
    // --- AES stage ---
    let aes_cipher = Aes256GcmSiv::new_from_slice(aes_key)
        .map_err(|e| anyhow!("Invalid AES key length: {:?}", e))?;

    // Generate a random 12-byte nonce
    let mut aes_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut aes_nonce_bytes);
    let aes_nonce = AesNonce::from_slice(&aes_nonce_bytes);

    // Encrypt the plaintext data with AES
    let aes_ciphertext = aes_cipher
        .encrypt(aes_nonce, &data[..])
        .map_err(|e| anyhow!("AES encryption error: {:?}", e))?;

    // Zeroize the plaintext data (in-place)
    data.zeroize();

    // Combine nonce + AES ciphertext to feed into XChaCha
    let mut aes_encrypted = Vec::with_capacity(12 + aes_ciphertext.len());
    aes_encrypted.extend_from_slice(&aes_nonce_bytes);
    aes_encrypted.extend_from_slice(&aes_ciphertext);

    // --- XChaCha stage ---
    let x_cipher = XChaCha20Poly1305::new(XKey::from_slice(xcha_key));

    // Generate 24-byte XChaCha nonce
    let mut x_nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut x_nonce_bytes);
    let x_nonce = XNonce::from_slice(&x_nonce_bytes);

    let x_ciphertext = x_cipher
        .encrypt(x_nonce, &aes_encrypted[..])
        .map_err(|e| anyhow!("XChaCha encryption error: {:?}", e))?;

    // Zeroize the AES ciphertext
    aes_encrypted.zeroize();

    // Format final output: 24-byte XChaCha nonce + XChaCha ciphertext
    let mut final_output = Vec::with_capacity(24 + x_ciphertext.len());
    final_output.extend_from_slice(&x_nonce_bytes);
    final_output.extend_from_slice(&x_ciphertext);

    Ok(final_output)
}

/// Decrypt in two stages (reverse order):
/// 1) XChaCha20-Poly1305
/// 2) AES-256-GCM-SIV
fn decrypt_double(data: &mut [u8], aes_key: &[u8; 32], xcha_key: &[u8; 32]) -> Result<Vec<u8>> {
    // Expect at least 24 bytes for the XChaCha nonce
    if data.len() < 24 {
        return Err(anyhow!("Data too short to contain XChaCha nonce"));
    }

    let (x_nonce_bytes, x_ciphertext) = data.split_at(24);

    let x_cipher = XChaCha20Poly1305::new(XKey::from_slice(xcha_key));
    let plaintext_of_x = x_cipher
        .decrypt(XNonce::from_slice(x_nonce_bytes), x_ciphertext)
        .map_err(|e| anyhow!("XChaCha decryption error: {:?}", e))?;

    // Zeroize the original encrypted input
    data.zeroize();

    // Now plaintext_of_x should contain [12-byte AES nonce | AES ciphertext+tag]
    if plaintext_of_x.len() < 12 {
        return Err(anyhow!("Decrypted data too short for AES nonce"));
    }

    let (aes_nonce_bytes, aes_ciphertext) = plaintext_of_x.split_at(12);

    let aes_cipher = Aes256GcmSiv::new_from_slice(aes_key)
        .map_err(|e| anyhow!("Invalid AES key length: {:?}", e))?;

    let final_plaintext = aes_cipher
        .decrypt(AesNonce::from_slice(aes_nonce_bytes), aes_ciphertext)
        .map_err(|e| anyhow!("AES decryption error: {:?}", e))?;

    // Zeroize intermediate
    let mut temp = plaintext_of_x;
    temp.zeroize();

    Ok(final_plaintext)
}

