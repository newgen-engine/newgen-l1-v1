use std::path::{Path, PathBuf};

pub const EFFECTIVE_DATA_DIR_ENV: &str = "NEWGEN_EFFECTIVE_DATA_DIR";

pub const CONFIG_DIR_ENV: &str = "NEWGEN_CONFIG_DIR";

#[derive(Clone, Debug)]
pub struct NodePaths {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub db_dir: PathBuf,
    pub snapshots_dir: PathBuf,
    pub logs_dir: PathBuf,
}

pub fn snapshot_v2_auto_dir_from_root(snapshots_root: &Path) -> PathBuf {
    snapshots_root.join("auto")
}

pub fn snapshot_v2_latest_dir_from_root(snapshots_root: &Path) -> PathBuf {
    // Cadenced checkpoint/latest bundle used for prune safety and durable snapshot retention.
    snapshot_v2_auto_dir_from_root(snapshots_root).join("latest")
}

pub fn snapshot_v2_bootstrap_latest_dir_from_root(snapshots_root: &Path) -> PathBuf {
    // Freshest bootstrap-oriented bundle used by RRv3 GetSnapshotV2Latest and runtime adverts.
    snapshot_v2_auto_dir_from_root(snapshots_root).join("bootstrap_latest")
}

pub fn snapshot_v2_last_meta_path_from_root(snapshots_root: &Path) -> PathBuf {
    snapshot_v2_auto_dir_from_root(snapshots_root).join("last_snapshot_meta.json")
}

pub fn snapshot_v2_last_checkpoint_meta_path_from_root(snapshots_root: &Path) -> PathBuf {
    snapshot_v2_auto_dir_from_root(snapshots_root).join("last_checkpoint_snapshot_meta.json")
}

pub fn snapshot_v2_last_bootstrap_meta_path_from_root(snapshots_root: &Path) -> PathBuf {
    snapshot_v2_auto_dir_from_root(snapshots_root).join("last_bootstrap_snapshot_meta.json")
}

pub fn snapshot_v2_legacy_latest_dir_from_root(snapshots_root: &Path) -> PathBuf {
    snapshots_root.join("snapshot_v2_latest")
}

impl NodePaths {
    fn normalize_path_against_data_dir(data_dir: &Path, candidate: PathBuf) -> PathBuf {
        if candidate.is_absolute() {
            candidate
        } else {
            data_dir.join(candidate)
        }
    }

    pub fn config_dir_from_data_dir(data_dir: &Path) -> PathBuf {
        match std::env::var(CONFIG_DIR_ENV) {
            Ok(v) if !v.trim().is_empty() => {
                Self::normalize_path_against_data_dir(data_dir, PathBuf::from(v.trim()))
            }
            _ => data_dir.join("config"),
        }
    }

    fn effective_data_dir_hint() -> Option<PathBuf> {
        let raw = std::env::var(EFFECTIVE_DATA_DIR_ENV).ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let candidate = PathBuf::from(trimmed);
        let normalized = if candidate.is_absolute() {
            candidate
        } else if let Ok(cwd) = std::env::current_dir() {
            cwd.join(candidate)
        } else {
            candidate
        };
        Some(std::fs::canonicalize(&normalized).unwrap_or(normalized))
    }

    pub fn resolve_config_path(path: impl AsRef<Path>) -> PathBuf {
        let path = path.as_ref();
        if path.is_absolute() {
            return path.to_path_buf();
        }

        let effective_data_dir = Self::effective_data_dir_hint();

        match std::env::var(CONFIG_DIR_ENV) {
            Ok(v) if !v.trim().is_empty() => {
                let raw_config_dir = PathBuf::from(v.trim());
                let config_dir = match effective_data_dir.as_ref() {
                    Some(data_dir) => {
                        Self::normalize_path_against_data_dir(data_dir, raw_config_dir)
                    }
                    None => raw_config_dir,
                };
                match path.file_name() {
                    Some(name) => config_dir.join(name),
                    None => config_dir.join(path),
                }
            }
            _ => match effective_data_dir {
                Some(data_dir) => data_dir.join(path),
                None => path.to_path_buf(),
            },
        }
    }

    pub fn from_data_dir(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            config_dir: Self::config_dir_from_data_dir(&data_dir),
            db_dir: data_dir.join("db"),
            snapshots_dir: data_dir.join("snapshots"),
            logs_dir: data_dir.join("logs"),
            data_dir,
        }
    }

    pub fn snapshot_v2_auto_dir(&self) -> PathBuf {
        snapshot_v2_auto_dir_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_latest_dir(&self) -> PathBuf {
        snapshot_v2_latest_dir_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_bootstrap_latest_dir(&self) -> PathBuf {
        snapshot_v2_bootstrap_latest_dir_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_last_meta_path(&self) -> PathBuf {
        snapshot_v2_last_meta_path_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_last_checkpoint_meta_path(&self) -> PathBuf {
        snapshot_v2_last_checkpoint_meta_path_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_last_bootstrap_meta_path(&self) -> PathBuf {
        snapshot_v2_last_bootstrap_meta_path_from_root(&self.snapshots_dir)
    }

    pub fn snapshot_v2_legacy_latest_dir(&self) -> PathBuf {
        snapshot_v2_legacy_latest_dir_from_root(&self.snapshots_dir)
    }

    pub fn genesis_path(&self) -> PathBuf {
        self.config_dir.join("genesis.json")
    }
    pub fn governance_path(&self) -> PathBuf {
        self.config_dir.join("governance.json")
    }
    pub fn p2p_policy_path(&self) -> PathBuf {
        self.config_dir.join("p2p_policy.toml")
    }
    pub fn economy_policy_path(&self) -> PathBuf {
        self.config_dir.join("economy_policy.json")
    }
    pub fn security_policy_path(&self) -> PathBuf {
        self.config_dir.join("security_policy.toml")
    }

    pub fn tx_policy_path(&self) -> PathBuf {
        self.config_dir.join("tx_policy.toml")
    }

    /// Returns a per-node log file path, e.g. logs/newgen_engine_A.log
    /// Also ensures logs_dir exists (best-effort).
    pub fn log_file_path(&self, node_tag: &str) -> PathBuf {
        let _ = std::fs::create_dir_all(&self.logs_dir);
        let clean: String = node_tag
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        self.logs_dir.join(format!("newgen_engine_{}.log", clean))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn with_env_lock<F: FnOnce()>(f: F) {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        f();
    }

    #[test]
    fn from_data_dir_builds_expected_layout() {
        with_env_lock(|| {
            std::env::remove_var(CONFIG_DIR_ENV);
            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);
            let p = NodePaths::from_data_dir("/tmp/newgen/nodeA");
            assert!(p.config_dir.ends_with("config"));
            assert!(p.db_dir.ends_with("db"));
            assert!(p.snapshots_dir.ends_with("snapshots"));
            assert!(p.logs_dir.ends_with("logs"));
            assert!(p.genesis_path().ends_with("config/genesis.json"));
            assert!(p
                .security_policy_path()
                .ends_with("config/security_policy.toml"));
        });
    }

    #[test]
    fn log_file_path_sanitizes_node_tag() {
        with_env_lock(|| {
            std::env::remove_var(CONFIG_DIR_ENV);
            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);
            let base = std::env::temp_dir().join("newgen_node_paths_test");
            let paths = NodePaths::from_data_dir(base);
            let p = paths.log_file_path("A/B:C");
            assert!(p.ends_with("logs/newgen_engine_A_B_C.log"));
            assert!(paths.logs_dir.exists());
            let _ = std::fs::remove_dir_all(paths.data_dir.clone());
        });
    }

    #[test]
    fn resolve_config_path_honors_env_override() {
        with_env_lock(|| {
            let cfg = std::env::temp_dir().join("newgen_cfg_override_test");
            std::fs::create_dir_all(&cfg).unwrap();
            std::env::set_var(CONFIG_DIR_ENV, &cfg);
            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);

            let resolved = NodePaths::resolve_config_path("config/genesis.json");
            assert_eq!(resolved, cfg.join("genesis.json"));

            let paths = NodePaths::from_data_dir("/tmp/newgen/nodeB");
            assert_eq!(paths.config_dir, cfg);

            std::env::remove_var(CONFIG_DIR_ENV);
            let _ = std::fs::remove_dir_all(cfg);
        });
    }

    #[test]
    fn resolve_config_path_defaults_against_effective_data_dir_hint() {
        with_env_lock(|| {
            std::env::remove_var(CONFIG_DIR_ENV);
            let data_dir = std::env::temp_dir().join("newgen_node_paths_test_nodeE");
            std::fs::create_dir_all(&data_dir).unwrap();
            let data_dir = std::fs::canonicalize(&data_dir).unwrap_or(data_dir);
            std::env::set_var(EFFECTIVE_DATA_DIR_ENV, &data_dir);

            let resolved = NodePaths::resolve_config_path("config/genesis.json");
            assert_eq!(resolved, data_dir.join("config").join("genesis.json"));

            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);
            let _ = std::fs::remove_dir_all(&data_dir);
        });
    }

    #[test]
    fn resolve_config_path_relative_override_is_anchored_to_effective_data_dir_hint() {
        with_env_lock(|| {
            let data_dir = std::env::temp_dir().join("newgen_node_paths_test_nodeF");
            std::fs::create_dir_all(&data_dir).unwrap();
            let data_dir = std::fs::canonicalize(&data_dir).unwrap_or(data_dir);
            std::env::set_var(CONFIG_DIR_ENV, "custom-config");
            std::env::set_var(EFFECTIVE_DATA_DIR_ENV, &data_dir);

            let resolved = NodePaths::resolve_config_path("config/governance.json");
            assert_eq!(
                resolved,
                data_dir.join("custom-config").join("governance.json")
            );

            std::env::remove_var(CONFIG_DIR_ENV);
            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);
            let _ = std::fs::remove_dir_all(&data_dir);
        });
    }

    #[test]
    fn snapshot_v2_helpers_use_auto_latest_layout() {
        let paths = NodePaths::from_data_dir("/tmp/newgen/nodeC");
        assert!(paths.snapshot_v2_auto_dir().ends_with("snapshots/auto"));
        assert!(paths
            .snapshot_v2_latest_dir()
            .ends_with("snapshots/auto/latest"));
        assert!(paths
            .snapshot_v2_bootstrap_latest_dir()
            .ends_with("snapshots/auto/bootstrap_latest"));
        assert!(paths
            .snapshot_v2_last_meta_path()
            .ends_with("snapshots/auto/last_snapshot_meta.json"));
        assert!(paths
            .snapshot_v2_legacy_latest_dir()
            .ends_with("snapshots/snapshot_v2_latest"));
    }

    #[test]
    fn config_dir_env_relative_is_resolved_against_data_dir() {
        with_env_lock(|| {
            std::env::set_var(CONFIG_DIR_ENV, "custom-config");
            std::env::remove_var(EFFECTIVE_DATA_DIR_ENV);
            let paths = NodePaths::from_data_dir("/tmp/newgen/nodeD");
            assert_eq!(
                paths.config_dir,
                PathBuf::from("/tmp/newgen/nodeD").join("custom-config")
            );
            std::env::remove_var(CONFIG_DIR_ENV);
        });
    }
}
