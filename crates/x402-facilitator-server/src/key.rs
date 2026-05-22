//! Facilitator's own Falcon key, used to sign acks returned from the
//! hot-path payment handler. Stored under `FACILITATOR_KEYSTORE_PATH`
//! on first boot; reused on subsequent boots.

use std::fs;
use std::path::PathBuf;

use miden_keystore::{FilesystemKeyStore, KeyStore};
use miden_protocol::Word;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

use crate::error::{FacilitatorError, Result};

/// Wraps the facilitator's Falcon keypair on disk.
#[derive(Clone)]
pub struct FacilitatorKey {
    inner: FilesystemKeyStore<ChaCha20Rng>,
    commitment: Word,
}

impl FacilitatorKey {
    /// Load or initialize a single Falcon keypair at `keystore_dir`. If
    /// `commitment_marker.txt` exists (set on first boot), that key is
    /// reused; otherwise a fresh key is generated and the marker is
    /// written.
    pub fn load_or_create(keystore_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&keystore_dir)
            .map_err(|e| FacilitatorError::Internal(format!("keystore mkdir: {e}")))?;
        let marker = keystore_dir.join("commitment_marker.txt");

        let inner = FilesystemKeyStore::with_rng(keystore_dir.clone(), ChaCha20Rng::from_os_rng())
            .map_err(|e| FacilitatorError::Internal(format!("keystore: {e}")))?;

        let commitment = if marker.is_file() {
            let hex = fs::read_to_string(&marker)
                .map_err(|e| FacilitatorError::Internal(format!("read marker: {e}")))?;
            parse_word_hex(hex.trim())?
        } else {
            let word = inner
                .generate_key()
                .map_err(|e| FacilitatorError::Internal(format!("keygen: {e}")))?;
            fs::write(&marker, word_to_hex(word))
                .map_err(|e| FacilitatorError::Internal(format!("write marker: {e}")))?;
            word
        };

        Ok(Self { inner, commitment })
    }

    pub fn commitment_hex(&self) -> String {
        word_to_hex(self.commitment)
    }

    /// Sign an arbitrary `Word` digest with the facilitator's Falcon
    /// secret key. Returns hex-encoded signature bytes.
    pub fn sign_word_hex(&self, msg: Word) -> Result<String> {
        use miden_protocol::utils::serde::Serializable;
        let sig = self
            .inner
            .sign(self.commitment, msg)
            .map_err(|e| FacilitatorError::Internal(format!("sign: {e}")))?;
        Ok(format!("0x{}", hex::encode(sig.to_bytes())))
    }

    /// Sign a message and return the prepared signature as Felts
    /// (suitable for injection into the advice map / advice stack).
    pub fn sign_prepared(&self, msg: Word) -> Result<Vec<miden_protocol::Felt>> {
        let raw_sig = self
            .inner
            .sign(self.commitment, msg)
            .map_err(|e| FacilitatorError::Internal(format!("sign: {e}")))?;
        // Wrap the raw Falcon signature into the auth::Signature enum
        // so we can call to_prepared_signature().
        let auth_sig = miden_protocol::account::auth::Signature::Falcon512Poseidon2(raw_sig);
        Ok(auth_sig.to_prepared_signature(msg))
    }

    /// Return the facilitator's public key commitment as a Word.
    pub fn commitment_word(&self) -> Word {
        self.commitment
    }
}

pub fn word_to_hex(w: Word) -> String {
    use miden_protocol::utils::serde::Serializable;
    format!("0x{}", hex::encode(w.to_bytes()))
}

pub fn parse_word_hex(s: &str) -> Result<Word> {
    use miden_protocol::utils::serde::Deserializable;
    let stripped = s.trim_start_matches("0x");
    let bytes = hex::decode(stripped)
        .map_err(|e| FacilitatorError::Malformed(format!("hex Word: {e}")))?;
    Word::read_from_bytes(&bytes)
        .map_err(|e| FacilitatorError::Malformed(format!("Word from bytes: {e}")))
}
