use serde_json::json;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

fn value_after(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|p| p[0] == flag)
        .map(|p| p[1].clone())
        .ok_or_else(|| format!("missing {flag}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agb-gate4-live-workload: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let config = value_after(&args, "--config")?;
    let secret = value_after(&args, "--secret")?;
    let trigger = value_after(&args, "--trigger")?;
    let state = value_after(&args, "--state")?;
    let loopback_port = value_after(&args, "--loopback-port")?
        .parse::<u16>()
        .map_err(|_| "invalid loopback port")?;
    let external_address = value_after(&args, "--external-address")?;
    let external_port = value_after(&args, "--external-port")?
        .parse::<u16>()
        .map_err(|_| "invalid external port")?;

    TcpStream::connect(("127.0.0.1", loopback_port))
        .map_err(|e| format!("loopback connect: {e}"))?;
    for _ in 0..4 {
        File::open(&config).map_err(|e| format!("config open: {e}"))?;
    }
    File::open(&secret).map_err(|e| format!("secret open: {e}"))?;
    write_state(
        &state,
        json!({"phase":"captured", "pid":std::process::id()}),
    )?;

    let mut heartbeat = Instant::now();
    while !Path::new(&trigger).exists() {
        if heartbeat.elapsed() >= Duration::from_secs(1) {
            TcpStream::connect(("127.0.0.1", loopback_port))
                .map_err(|e| format!("loopback heartbeat: {e}"))?;
            heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(25));
    }
    let result = TcpStream::connect((external_address.as_str(), external_port));
    let (outcome, errno) = classify(result);
    write_state(
        &state,
        json!({"phase":"enforced", "pid":std::process::id(), "outcome":outcome, "errno":errno}),
    )?;
    heartbeat = Instant::now();
    while Path::new(&trigger).exists() {
        if heartbeat.elapsed() >= Duration::from_secs(1) {
            TcpStream::connect(("127.0.0.1", loopback_port))
                .map_err(|e| format!("recovery loopback heartbeat: {e}"))?;
            heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(25));
    }
    let recovery = TcpStream::connect((external_address.as_str(), external_port));
    let (recovery_outcome, recovery_errno) = classify(recovery);
    write_state(
        &state,
        json!({"phase":"complete", "pid":std::process::id(), "outcome":outcome, "errno":errno, "recovery_outcome":recovery_outcome, "recovery_errno":recovery_errno}),
    )?;
    Ok(())
}

fn classify(result: std::io::Result<TcpStream>) -> (&'static str, Option<i32>) {
    match result {
        Ok(_) => ("connected", None),
        Err(error) => (
            if error.raw_os_error() == Some(libc::EACCES) {
                "EACCES"
            } else {
                "other-error"
            },
            error.raw_os_error(),
        ),
    }
}

fn write_state(path: &str, value: serde_json::Value) -> Result<(), String> {
    let temporary = format!("{path}.tmp");
    let mut file = File::create(&temporary).map_err(|e| e.to_string())?;
    writeln!(file, "{value}").map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(temporary, path).map_err(|e| e.to_string())
}
