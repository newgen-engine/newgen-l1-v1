pub const RR_V2: &str = "/newgen/sync/1"; // compat con la tua RR attuale
pub const RR_V3: &str = "/newgen/rr/3"; // Step 57

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_are_stable_and_versioned() {
        assert!(RR_V2.starts_with("/newgen/"));
        assert!(RR_V3.starts_with("/newgen/"));
        assert_ne!(RR_V2, RR_V3);
        assert!(RR_V2.ends_with("/1"));
        assert!(RR_V3.ends_with("/3"));
    }
}
