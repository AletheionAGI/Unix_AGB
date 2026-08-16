use std::env;
use std::path::PathBuf;

fn authorize() -> Result<(), String> {
    let token = env::var("AGB_ADMIN_TOKEN").map_err(|_| "AGB_ADMIN_TOKEN is required")?;
    if token.is_empty() {
        return Err("AGB_ADMIN_TOKEN is empty".into());
    }
    if let Ok(path) = env::var("AGB_ADMIN_TOKEN_FILE") {
        let expected = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if token.trim_end() != expected.trim_end() {
            return Err("invalid admin token".into());
        }
    }
    Ok(())
}

fn main() -> Result<(), String> {
    authorize()?;
    let command = env::args().nth(1).unwrap_or_else(|| "list".into());
    let path = PathBuf::from(
        env::args()
            .nth(2)
            .unwrap_or_else(|| "var/policy-cache.jsonl".into()),
    );
    let rotated = PathBuf::from(format!("{}.rotated", path.display()));
    match command.as_str() {
        "rotate" => {
            if path.exists() {
                std::fs::rename(&path, &rotated).map_err(|e| e.to_string())?;
            }
            println!("rotated={}", rotated.display());
        }
        "rollback" => {
            if path.exists() {
                return Err("active cache already exists".into());
            }
            std::fs::rename(&rotated, &path).map_err(|e| e.to_string())?;
            println!("restored={}", path.display());
        }
        "list" => {
            println!("active={} exists={}", path.display(), path.exists());
            println!("rotated={} exists={}", rotated.display(), rotated.exists());
        }
        _ => return Err("usage: agb-cachectl [rotate|rollback|list] [CACHE_PATH]".into()),
    }
    Ok(())
}
