use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use unix_agb::store::CanonicalStore;

const DEFAULT_STORE: &str = "var/events.jsonl";

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  agbctl status [--store PATH]\n  agbctl events tail [--store PATH] [--limit N]"
    );
    std::process::exit(2);
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agbctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let store_path = value_after(&args, "--store").unwrap_or_else(|| DEFAULT_STORE.into());
    match args.get(1).map(String::as_str) {
        Some("status") => {
            let store = CanonicalStore::open(&store_path)?;
            println!("mode: audit-only");
            println!("store: {}", store.path().display());
            println!("events: {}", store.event_count());
            println!("namespaces: {}", store.namespace_count());
            println!("enforcement: fake (never applied)");
        }
        Some("events") if args.get(2).map(String::as_str) == Some("tail") => {
            let limit = value_after(&args, "--limit")
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| "invalid --limit".to_string())
                })
                .transpose()?
                .unwrap_or(20);
            if !std::path::Path::new(&store_path).exists() {
                return Ok(());
            }
            let lines: Vec<String> =
                BufReader::new(File::open(&store_path).map_err(|e| e.to_string())?)
                    .lines()
                    .collect::<Result<_, _>>()
                    .map_err(|e| e.to_string())?;
            for line in lines.iter().rev().take(limit).rev() {
                println!("{line}");
            }
        }
        _ => usage(),
    }
    Ok(())
}
