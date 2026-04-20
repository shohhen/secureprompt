//! Integration tests for the KMS abstraction layer.
//!
//! Environment variables are process-global, so tests that mutate them must
//! run under a mutex to avoid races when the test harness runs them in
//! parallel threads.

use secureprompt_common::kms::{kms_backend_from_env, FileKms, KmsBackend};
use std::sync::{Arc, Mutex};

/// Global lock serialising all env-var-dependent tests in this file.
static ENV_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

fn make_file_kms() -> Arc<dyn KmsBackend> {
    // 32 zero-bytes base64-encoded (STANDARD) = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    std::env::set_var("KMS_FILE_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    Arc::new(FileKms::from_env().expect("FileKms construction"))
}

#[tokio::test]
async fn file_kms_roundtrip() {
    let _g = ENV_LOCK.lock().unwrap();
    let kms = make_file_kms();
    let plaintext = b"super-secret-api-key-value";
    let ciphertext = kms.encrypt(plaintext).await.expect("encrypt");
    assert_ne!(ciphertext, plaintext.to_vec());
    let recovered = kms.decrypt(&ciphertext).await.expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[tokio::test]
async fn file_kms_rejects_short_key() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("KMS_FILE_KEY", "c2hvcnQ="); // base64("short") = 5 bytes
    let result = FileKms::from_env();
    assert!(result.is_err());
    let msg = format!("{:#}", result.err().unwrap());
    assert!(msg.contains("32 bytes"), "got: {msg}");
}

#[tokio::test]
async fn file_kms_rejects_invalid_base64() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("KMS_FILE_KEY", "not@@valid!!base64");
    let result = FileKms::from_env();
    assert!(result.is_err());
    let msg = format!("{:#}", result.err().unwrap());
    assert!(msg.contains("base64"), "got: {msg}");
}

#[tokio::test]
async fn kms_backend_from_env_file() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("KMS_BACKEND", "file");
    std::env::set_var("KMS_FILE_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let result = kms_backend_from_env();
    assert!(result.is_ok(), "{}", result.err().unwrap());
}

#[tokio::test]
async fn kms_backend_from_env_unknown() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("KMS_BACKEND", "hsm");
    let result = kms_backend_from_env();
    assert!(result.is_err());
    let msg = format!("{:#}", result.err().unwrap());
    assert!(msg.contains("hsm"), "got: {msg}");
}

#[tokio::test]
#[ignore]
async fn vault_kms_constructs_with_token() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::set_var("KMS_BACKEND", "vault");
    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_TOKEN", "dev-root-token");
    let result = kms_backend_from_env();
    assert!(result.is_ok(), "{}", result.err().unwrap());
}
