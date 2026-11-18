// ===================================
// FILE: src/bin/storage_migrate.rs
// Tool ufficiale di manutenzione storage/migrazioni (mainnet-grade).
//
// Politica attuale (prelaunch reset strategy):
// - il backend runtime attivo parte da schema pulito
// - il tool opera solo sul backend runtime Fjall attivo
// - il bootstrap normale del nodo non deve dipendere dal ramo legacy
//
// Esempi:
//   cargo run --bin storage_migrate -- migrate-db --path db
//   cargo run --bin storage_migrate -- verify-db --full --path db
// ===================================

use newgen_engine::storage::{DbStore, StorageError, VerifyReport, DB_PATH};

fn print_help() {
    eprintln!("storage_migrate commands:");
    eprintln!("  note: this tool operates only on the canonical Fjall runtime backend");
    eprintln!(
        "  migrate-db [--path <db>]               # runtime Fjall schema check only; active backend bootstrap remains clean"
    );
    eprintln!("  verify-db [--full] [--path <db>]");
    eprintln!("  repair-db [--verify-after|--no-verify-after] [--path <db>]");
    eprintln!("  export-snapshot <file> [--with-state|--no-state] [--path <db>]  # legacy v1; disabled in public mode");
    eprintln!("  import-snapshot <file> [--wipe-state|--keep-state] [--path <db>]  # legacy v1; disabled in public mode");
}

fn open_storage_or_exit(db_path: &str) -> DbStore {
    match DbStore::open(db_path) {
        Ok(s) => s,
        Err(StorageError::InterprocessOpenConflict { path, message }) => {
            eprintln!(
                "storage open refused: runtime db dir already in use (path={}, detail={})",
                path, message
            );
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("storage open failed: {:?}", e);
            std::process::exit(2);
        }
    }
}

fn print_report(rep: &VerifyReport) {
    eprintln!("ok            : {}", rep.ok);
    eprintln!("height        : {:?}", rep.height);
    eprintln!("needs_recovery: {}", rep.needs_recovery);
    eprintln!("issues        : {}", rep.issues.len());
    for (i, s) in rep.issues.iter().enumerate() {
        eprintln!("  {:>2}. {}", i + 1, s);
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        print_help();
        std::process::exit(2);
    }

    let cmd = argv[1].as_str();
    if matches!(cmd, "export-snapshot" | "import-snapshot")
        && newgen_engine::runtime_mode::public_mode_enabled()
    {
        eprintln!(
            "legacy snapshot v1 import/export is disabled in public mode; use export-snapshot-v2/import-snapshot-v2"
        );
        std::process::exit(2);
    }

    let mut db_path: String = DB_PATH.to_string();
    let mut full = false;
    let mut include_state = true;
    let mut wipe_state = true;
    let mut verify_after = true;

    let mut positional: Vec<String> = Vec::new();
    let mut i = 2usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "--path" | "--db" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("missing value for --path");
                    std::process::exit(2);
                }
                db_path = argv[i].clone();
            }
            "--full" => full = true,
            "--quick" => full = false,
            "--with-state" => include_state = true,
            "--no-state" => include_state = false,
            "--wipe-state" => wipe_state = true,
            "--keep-state" => wipe_state = false,
            "--verify-after" => verify_after = true,
            "--no-verify-after" => verify_after = false,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    match cmd {
        "migrate-db" => {
            let _storage = open_storage_or_exit(&db_path);
            if let Err(e) = newgen_engine::storage::ensure_runtime_storage_schema_current() {
                eprintln!("runtime schema check failed: {}", e);
                std::process::exit(2);
            }
            eprintln!(
                "OK: runtime storage schema is current (path={}). {}",
                db_path,
                newgen_engine::storage::runtime_storage_bootstrap_strategy_note()
            );
            std::process::exit(0);
        }
        "verify-db" => {
            let storage = open_storage_or_exit(&db_path);
            match storage.verify_db(full) {
                Ok(rep) => {
                    print_report(&rep);
                    std::process::exit(if rep.ok && !rep.needs_recovery { 0 } else { 2 });
                }
                Err(e) => {
                    eprintln!("verify-db failed: {:?}", e);
                    std::process::exit(2);
                }
            }
        }
        "repair-db" => {
            let storage = open_storage_or_exit(&db_path);
            match storage.repair_db(verify_after) {
                Ok(rep) => {
                    print_report(&rep);
                    std::process::exit(if rep.ok { 0 } else { 2 });
                }
                Err(e) => {
                    eprintln!("repair-db failed: {:?}", e);
                    std::process::exit(2);
                }
            }
        }
        "export-snapshot" => {
            if positional.len() != 1 {
                eprintln!("export-snapshot requires <file>");
                print_help();
                std::process::exit(2);
            }
            let out = &positional[0];
            let storage = open_storage_or_exit(&db_path);
            if let Err(e) = storage.export_snapshot(out, include_state) {
                eprintln!("export-snapshot failed: {:?}", e);
                std::process::exit(2);
            }
            eprintln!(
                "OK: export-snapshot completed (path={}, file={}, include_state_nodes={})",
                db_path, out, include_state
            );
            std::process::exit(0);
        }
        "import-snapshot" => {
            if positional.len() != 1 {
                eprintln!("import-snapshot requires <file>");
                print_help();
                std::process::exit(2);
            }
            let inp = &positional[0];
            let storage = open_storage_or_exit(&db_path);
            if let Err(e) = storage.import_snapshot(inp, wipe_state) {
                eprintln!("import-snapshot failed: {:?}", e);
                std::process::exit(2);
            }
            eprintln!(
                "OK: import-snapshot completed (path={}, file={}, wipe_state_nodes={})",
                db_path, inp, wipe_state
            );
            std::process::exit(0);
        }
        _ => {
            eprintln!("unknown command: {}", cmd);
            print_help();
            std::process::exit(2);
        }
    }
}
