use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: u64,

    /// Payload opzionale per record **consensus-critical** (es. staking/registry in SMT).
    ///
    /// ⚠️ Nota: questo campo cambia la serializzazione bincode del leaf SMT.
    /// È previsto fare wipe/rebuild dello stato quando si introduce.
    #[serde(default)]
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_account_state_is_zeroed() {
        let st = AccountState::default();
        assert_eq!(st.nonce, 0);
        assert_eq!(st.balance, 0);
        assert!(st.data.is_empty());
    }

    #[test]
    fn serde_roundtrip_preserves_optional_data() {
        let st = AccountState {
            nonce: 7,
            balance: 99,
            data: vec![1, 2, 3, 4],
        };
        let enc = serde_json::to_vec(&st).unwrap();
        let dec: AccountState = serde_json::from_slice(&enc).unwrap();
        assert_eq!(dec, st);
    }
}
