use serde_json::json;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::TcpStream;

#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

fn value_after(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("missing {flag}"))
}

fn apply_read_denial() -> Result<(), String> {
    #[cfg(not(target_arch = "x86_64"))]
    return Err("the laboratory Landlock adapter currently supports x86_64 only".into());

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let attr = RulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
        };
        let fd = libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        ) as libc::c_int;
        if fd < 0 {
            return Err(format!(
                "landlock_create_ruleset: {}",
                io::Error::last_os_error()
            ));
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::close(fd);
            return Err(format!(
                "PR_SET_NO_NEW_PRIVS: {}",
                io::Error::last_os_error()
            ));
        }
        if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) != 0 {
            libc::close(fd);
            return Err(format!(
                "landlock_restrict_self: {}",
                io::Error::last_os_error()
            ));
        }
        libc::close(fd);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agb-lab-workload: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let case = value_after(&args, "--case")?;
    let secret = value_after(&args, "--secret")?;
    let config = value_after(&args, "--config")?;
    let port = value_after(&args, "--port")?
        .parse::<u16>()
        .map_err(|_| "invalid --port".to_string())?;

    match case.as_str() {
        "benign" => {
            File::open(&config).map_err(|error| format!("open config: {error}"))?;
        }
        "suspicious" => {
            TcpStream::connect(("127.0.0.1", port))
                .map_err(|error| format!("connect laboratory listener: {error}"))?;
        }
        _ => return Err("--case must be benign or suspicious".into()),
    }

    println!(
        "{}",
        json!({"ready": true, "pid": std::process::id(), "case": case})
    );
    io::stdout().flush().map_err(|error| error.to_string())?;

    let mut decision = String::new();
    io::stdin()
        .lock()
        .read_line(&mut decision)
        .map_err(|error| error.to_string())?;
    let effect = decision.trim();
    if effect == "DENY" {
        apply_read_denial()?;
    } else if effect != "ALLOW" {
        return Err(format!("unsupported decision: {effect}"));
    }

    match File::open(&secret) {
        Ok(_) => println!(
            "{}",
            json!({"case": case, "effect": effect, "open_result": "allowed", "errno": null})
        ),
        Err(error) => println!(
            "{}",
            json!({
                "case": case,
                "effect": effect,
                "open_result": "denied",
                "errno": error.raw_os_error()
            })
        ),
    }
    Ok(())
}
