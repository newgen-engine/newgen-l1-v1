use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct State {
    pub balances: HashMap<String, f64>,
}

impl State {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    pub fn update_balance(&mut self, user: &str, amount: f64) {
        *self.balances.entry(user.to_string()).or_insert(0.0) += amount;
    }

    pub fn get_balance(&self, user: &str) -> f64 {
        *self.balances.get(user).unwrap_or(&0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_balance_accumulates_and_missing_users_default_to_zero() {
        let mut st = State::new();
        st.update_balance("alice", 1.25);
        st.update_balance("alice", 0.75);
        st.update_balance("bob", 2.0);
        assert!((st.get_balance("alice") - 2.0).abs() < f64::EPSILON);
        assert!((st.get_balance("bob") - 2.0).abs() < f64::EPSILON);
        assert_eq!(st.get_balance("carol"), 0.0);
    }
}
