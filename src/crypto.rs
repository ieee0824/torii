use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::Argon2;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::db::VaultMetadata;
use crate::error::{EnvsGateError, Result};

const ARGON2_SALT_LEN: usize = 16;
const ARGON2_OUTPUT_LEN: usize = 64;
const AES_NONCE_LEN: usize = 12;
const DEK_LEN: usize = 32;

fn derive_master_seed(password: &str, salt: &[u8]) -> Result<[u8; ARGON2_OUTPUT_LEN]> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(ARGON2_OUTPUT_LEN))
            .map_err(|e| EnvsGateError::Crypto(format!("Argon2 params: {e}")))?,
    );

    let mut seed = [0u8; ARGON2_OUTPUT_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut seed)
        .map_err(|e| EnvsGateError::Crypto(format!("Argon2 hash: {e}")))?;

    Ok(seed)
}

fn derive_x25519_static(seed: &[u8; 32]) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from(*seed);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn derive_mlkem_keypair(
    seed: &[u8; 32],
) -> (
    <MlKem768 as KemCore>::DecapsulationKey,
    <MlKem768 as KemCore>::EncapsulationKey,
) {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (dk, ek) = MlKem768::generate(&mut rng);
    (dk, ek)
}

pub fn init_vault(password: &str) -> Result<(VaultMetadata, [u8; DEK_LEN])> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let mut master_seed = derive_master_seed(password, &salt)?;

    // Derive keypairs from master seed
    let x25519_seed: [u8; 32] = master_seed[..32].try_into().unwrap();
    let mlkem_seed: [u8; 32] = master_seed[32..64].try_into().unwrap();
    master_seed.zeroize();

    let (_x25519_static_secret, x25519_static_pub) = derive_x25519_static(&x25519_seed);
    let (_dk_kem, ek_kem) = derive_mlkem_keypair(&mlkem_seed);

    // Generate random DEK
    let mut dek = [0u8; DEK_LEN];
    rand::rngs::OsRng.fill_bytes(&mut dek);

    // Hybrid wrap DEK
    // 1. Ephemeral X25519
    let x25519_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_eph_pub = PublicKey::from(&x25519_eph_secret);
    let ss_x25519 = x25519_eph_secret.diffie_hellman(&x25519_static_pub);

    // 2. ML-KEM encapsulate
    let (ct_kem, ss_kem) = ek_kem
        .encapsulate(&mut OsRng)
        .map_err(|e| EnvsGateError::Crypto(format!("ML-KEM encapsulate: {e:?}")))?;

    // 3. Combine shared secrets with HKDF
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_kem.as_ref());
    ikm.extend_from_slice(ss_x25519.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"torii-hybrid-wrap"), &ikm);
    let mut wrapping_key = [0u8; 32];
    hk.expand(b"dek-wrapping", &mut wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("HKDF expand: {e}")))?;
    ikm.zeroize();

    // 4. Wrap DEK with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("AES key: {e}")))?;
    wrapping_key.zeroize();

    let mut wrap_nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut wrap_nonce_bytes);
    let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);

    let wrapped_dek = cipher
        .encrypt(wrap_nonce, dek.as_ref())
        .map_err(|e| EnvsGateError::Crypto(format!("DEK wrap: {e}")))?;

    // Serialize ML-KEM encapsulation key
    let ek_kem_bytes = ek_kem.as_bytes().to_vec();
    let ct_kem_bytes = ct_kem.as_slice().to_vec();

    let meta = VaultMetadata {
        salt: salt.to_vec(),
        ek_kem: ek_kem_bytes,
        x25519_pub: x25519_static_pub.as_bytes().to_vec(),
        ct_kem: ct_kem_bytes,
        x25519_eph: x25519_eph_pub.as_bytes().to_vec(),
        wrap_nonce: wrap_nonce_bytes.to_vec(),
        wrapped_dek,
    };

    Ok((meta, dek))
}

pub fn unwrap_dek(password: &str, meta: &VaultMetadata) -> Result<[u8; DEK_LEN]> {
    let mut master_seed = derive_master_seed(password, &meta.salt)?;

    let x25519_seed: [u8; 32] = master_seed[..32].try_into().unwrap();
    let mlkem_seed: [u8; 32] = master_seed[32..64].try_into().unwrap();
    master_seed.zeroize();

    let (x25519_static_secret, _) = derive_x25519_static(&x25519_seed);
    let (dk_kem, _) = derive_mlkem_keypair(&mlkem_seed);

    // X25519 DH with ephemeral public key
    let x25519_eph_pub_bytes: [u8; 32] = meta
        .x25519_eph
        .as_slice()
        .try_into()
        .map_err(|_| EnvsGateError::Crypto("Invalid x25519 ephemeral public key".into()))?;
    let x25519_eph_pub = PublicKey::from(x25519_eph_pub_bytes);
    let ss_x25519 = x25519_static_secret.diffie_hellman(&x25519_eph_pub);

    // ML-KEM decapsulate
    let ct_kem: Ciphertext<MlKem768> = ml_kem::array::Array::try_from(meta.ct_kem.as_slice())
        .map_err(|_| EnvsGateError::Crypto("Invalid ML-KEM ciphertext length".into()))?;
    let ss_kem = dk_kem
        .decapsulate(&ct_kem)
        .map_err(|_| EnvsGateError::Crypto("ML-KEM decapsulate failed".into()))?;

    // Combine shared secrets
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_kem.as_ref());
    ikm.extend_from_slice(ss_x25519.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"torii-hybrid-wrap"), &ikm);
    let mut wrapping_key = [0u8; 32];
    hk.expand(b"dek-wrapping", &mut wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("HKDF expand: {e}")))?;
    ikm.zeroize();

    // Unwrap DEK
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("AES key: {e}")))?;
    wrapping_key.zeroize();

    let wrap_nonce = Nonce::from_slice(&meta.wrap_nonce);
    let dek_bytes = cipher
        .decrypt(wrap_nonce, meta.wrapped_dek.as_ref())
        .map_err(|_| EnvsGateError::AuthenticationFailed)?;

    let dek: [u8; DEK_LEN] = dek_bytes
        .try_into()
        .map_err(|_| EnvsGateError::Crypto("Invalid DEK length".into()))?;

    Ok(dek)
}

pub fn wrap_dek(password: &str, dek: &[u8; DEK_LEN]) -> Result<VaultMetadata> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let mut master_seed = derive_master_seed(password, &salt)?;

    let x25519_seed: [u8; 32] = master_seed[..32].try_into().unwrap();
    let mlkem_seed: [u8; 32] = master_seed[32..64].try_into().unwrap();
    master_seed.zeroize();

    let (_x25519_static_secret, x25519_static_pub) = derive_x25519_static(&x25519_seed);
    let (_dk_kem, ek_kem) = derive_mlkem_keypair(&mlkem_seed);

    // Hybrid wrap DEK
    let x25519_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_eph_pub = PublicKey::from(&x25519_eph_secret);
    let ss_x25519 = x25519_eph_secret.diffie_hellman(&x25519_static_pub);

    let (ct_kem, ss_kem) = ek_kem
        .encapsulate(&mut OsRng)
        .map_err(|e| EnvsGateError::Crypto(format!("ML-KEM encapsulate: {e:?}")))?;

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_kem.as_ref());
    ikm.extend_from_slice(ss_x25519.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"torii-hybrid-wrap"), &ikm);
    let mut wrapping_key = [0u8; 32];
    hk.expand(b"dek-wrapping", &mut wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("HKDF expand: {e}")))?;
    ikm.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| EnvsGateError::Crypto(format!("AES key: {e}")))?;
    wrapping_key.zeroize();

    let mut wrap_nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut wrap_nonce_bytes);
    let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);

    let wrapped_dek = cipher
        .encrypt(wrap_nonce, dek.as_ref())
        .map_err(|e| EnvsGateError::Crypto(format!("DEK wrap: {e}")))?;

    let ek_kem_bytes = ek_kem.as_bytes().to_vec();
    let ct_kem_bytes = ct_kem.as_slice().to_vec();

    Ok(VaultMetadata {
        salt: salt.to_vec(),
        ek_kem: ek_kem_bytes,
        x25519_pub: x25519_static_pub.as_bytes().to_vec(),
        ct_kem: ct_kem_bytes,
        x25519_eph: x25519_eph_pub.as_bytes().to_vec(),
        wrap_nonce: wrap_nonce_bytes.to_vec(),
        wrapped_dek,
    })
}

pub fn encrypt_value(dek: &[u8; DEK_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| EnvsGateError::Crypto(format!("AES key: {e}")))?;

    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EnvsGateError::Crypto(format!("Encrypt: {e}")))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt_value(dek: &[u8; DEK_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(dek)
        .map_err(|e| EnvsGateError::Crypto(format!("AES key: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EnvsGateError::Crypto(format!("Decrypt: {e}")))?;

    Ok(plaintext)
}

use rand::RngCore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_vault_and_unwrap_dek_roundtrip() {
        let (meta, dek) = init_vault("test-password").unwrap();
        let recovered_dek = unwrap_dek("test-password", &meta).unwrap();
        assert_eq!(dek, recovered_dek);
    }

    #[test]
    fn unwrap_dek_wrong_password() {
        let (meta, _dek) = init_vault("correct-password").unwrap();
        let result = unwrap_dek("wrong-password", &meta);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_value_roundtrip() {
        let (_, dek) = init_vault("pw").unwrap();
        let plaintext = b"super-secret-value";
        let (nonce, ciphertext) = encrypt_value(&dek, plaintext).unwrap();
        let recovered = decrypt_value(&dek, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_dek_fails() {
        let (_, dek) = init_vault("pw1").unwrap();
        let (_, other_dek) = init_vault("pw2").unwrap();
        let (nonce, ciphertext) = encrypt_value(&dek, b"secret").unwrap();
        let result = decrypt_value(&other_dek, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let (_, dek) = init_vault("pw").unwrap();
        let (nonce, mut ciphertext) = encrypt_value(&dek, b"secret").unwrap();
        ciphertext[0] ^= 0xff;
        let result = decrypt_value(&dek, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn different_inits_produce_different_deks() {
        let (_, dek1) = init_vault("same-password").unwrap();
        let (_, dek2) = init_vault("same-password").unwrap();
        // DEKs are random, so they should differ even with same password
        assert_ne!(dek1, dek2);
    }

    #[test]
    fn encrypt_empty_value() {
        let (_, dek) = init_vault("pw").unwrap();
        let (nonce, ciphertext) = encrypt_value(&dek, b"").unwrap();
        let recovered = decrypt_value(&dek, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn encrypt_large_value() {
        let (_, dek) = init_vault("pw").unwrap();
        let large = vec![0xABu8; 1024 * 1024]; // 1MB
        let (nonce, ciphertext) = encrypt_value(&dek, &large).unwrap();
        let recovered = decrypt_value(&dek, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, large);
    }
}
