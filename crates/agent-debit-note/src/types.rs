use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::NoteStorage;

/// Storage layout for the AgentDebitNote.
///
/// 7 storage items:
///   [0-3]  agent_pubkey_commitment (Word)
///   [4]    user_account_id_suffix
///   [5]    user_account_id_prefix
///   [6]    expiry_block_height
pub struct AgentDebitNoteStorage {
    pub agent_pubkey_commitment: Word,
    pub user_account_id: AccountId,
    pub expiry_block_height: u32,
}

impl AgentDebitNoteStorage {
    pub fn new(
        agent_pubkey_commitment: Word,
        user_account_id: AccountId,
        expiry_block_height: u32,
    ) -> Self {
        Self {
            agent_pubkey_commitment,
            user_account_id,
            expiry_block_height,
        }
    }
}

impl From<AgentDebitNoteStorage> for NoteStorage {
    fn from(s: AgentDebitNoteStorage) -> Self {
        use miden_protocol::Felt;
        NoteStorage::new(vec![
            s.agent_pubkey_commitment[0],
            s.agent_pubkey_commitment[1],
            s.agent_pubkey_commitment[2],
            s.agent_pubkey_commitment[3],
            s.user_account_id.suffix(),
            s.user_account_id.prefix().as_felt(),
            Felt::new(s.expiry_block_height as u64),
        ])
        .expect("7 storage items should not exceed max")
    }
}
