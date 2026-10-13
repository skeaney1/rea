//! rea-agent: start a dedicated pi agent that answers a brief with REA evidence.
//!
//!   rea-agent run <brief.md> --out <dir> [--model <pattern>]
//!   rea-agent check
//!
//! Exit codes: 0 report written, 1 a prerequisite is missing, 2 bad arguments,
//! 3 the agent ran but wrote no REPORT.md.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const ROLE: &str = include_str!("../role.md");
const USAGE: &str = "usage: rea-agent run <brief.md> --out <dir> [--model <pattern>]\n       rea-agent check";
const REQUIRED_ENV: [&str; 3] = ["GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_ANALYSIS_PROVIDER"];

#[derive(Debug, PartialEq)]
enum Cli {
    Run { brief: PathBuf, out: PathBuf, model: Option<String> },
    Check,
}

fn parse(args: &[String]) -> Result<Cli, String> {
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 1 => Ok(Cli::Check),
        Some("run") => {
            let (mut brief, mut out, mut model) = (None, None, None);
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--out" => out = Some(rest.next().ok_or("--out needs a directory")?.into()),
                    "--model" => model = Some(rest.next().ok_or("--model needs a pattern")?.clone()),
                    flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
                    path if brief.is_none() => brief = Some(PathBuf::from(path)),
                    extra => return Err(format!("unexpected argument {extra}")),
                }
            }
            Ok(Cli::Run {
                brief: brief.ok_or("run needs a brief file")?,
                out: out.ok_or("run needs --out <dir>")?,
                model,
            })
        }
        _ => Err("expected `run` or `check`".into()),
    }
}

/// The skill ships with Storm's REA fork, so the agent follows whatever main says.
fn skill_dir() -> PathBuf {
    env::var_os("REA_SKILL_DIR").map(PathBuf::from).unwrap_or_else(|| {
        let home = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")).unwrap_or_default();
        Path::new(&home).join("projects/rea/skills/reverse-engineer-anything")
    })
}

fn pi_args(skill: &Path, role: &Path, brief: &Path, model: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--print", "--no-session", "--no-skills", "--tools", "read,bash,write,edit,grep,find,ls",
    ]
    .map(String::from)
    .to_vec();
    args.extend(["--skill".into(), skill.display().to_string()]);
    args.extend(["--append-system-prompt".into(), role.display().to_string()]);
    if let Some(model) = model {
        args.extend(["--model".into(), model.into()]);
    }
    args.push(format!("@{}", brief.display()));
    args.push("Carry out the brief above. Write REPORT.md in the current directory when done.".into());
    args
}

/// Problems that stop a run before it starts, worded for whoever has to fix them.
fn missing_prerequisites(skill: &Path) -> Vec<String> {
    let mut missing: Vec<String> = REQUIRED_ENV
        .iter()
        .filter(|name| env::var_os(name).is_none_or(|v| v.is_empty()))
        .map(|name| format!("environment variable {name} is not set (open a new terminal after setting it)"))
        .collect();
    if !skill.join("SKILL.md").is_file() {
        missing.push(format!("REA skill not found at {} (set REA_SKILL_DIR)", skill.display()));
    }
    for tool in ["pi", "rea"] {
        if which(tool).is_none() {
            missing.push(format!("`{tool}` is not on PATH"));
        }
    }
    missing
}

/// Create the run directory, write the role into it and return its absolute path. pi runs with
/// that directory as its cwd, so a relative `--out` would leave pi looking for `out/out/ROLE.md`,
/// and pi treats a missing `--append-system-prompt` file as literal text.
fn prepare_out(out: &Path) -> std::io::Result<PathBuf> {
    fs::create_dir_all(out)?;
    let out = std::path::absolute(out)?;
    fs::write(out.join("ROLE.md"), ROLE)?;
    Ok(out)
}

fn which(tool: &str) -> Option<PathBuf> {
    let exts = if cfg!(windows) { vec![".cmd", ".exe", ""] } else { vec![""] };
    env::split_paths(&env::var_os("PATH")?)
        .flat_map(|dir| exts.iter().map(move |ext| dir.join(format!("{tool}{ext}"))))
        .find(|path| path.is_file())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cli = match parse(&args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("rea-agent: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let skill = skill_dir();
    let missing = missing_prerequisites(&skill);
    for problem in &missing {
        eprintln!("rea-agent: {problem}");
    }
    let Cli::Run { brief, out, model } = cli else {
        if missing.is_empty() {
            println!("rea-agent: ready (skill {})", skill.display());
        }
        return ExitCode::from(if missing.is_empty() { 0 } else { 1 });
    };
    if !missing.is_empty() {
        return ExitCode::from(1);
    }
    let Ok(brief) = brief.canonicalize() else {
        eprintln!("rea-agent: brief {} does not exist", brief.display());
        return ExitCode::from(2);
    };
    if out.join("REPORT.md").exists() {
        eprintln!("rea-agent: {} already has a REPORT.md; use a new --out", out.display());
        return ExitCode::from(2);
    }
    let out = match prepare_out(&out) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("rea-agent: could not prepare {}: {e}", out.display());
            return ExitCode::from(1);
        }
    };
    let log = out.join("agent.log");
    let started = fs::File::create(&log)
        .and_then(|log_file| {
            let pi = which("pi").expect("checked above");
            Command::new(pi)
                .args(pi_args(&skill, &out.join("ROLE.md"), &brief, model.as_deref()))
                .current_dir(&out)
                .stdout(log_file.try_clone()?)
                .stderr(log_file)
                .status()
        });
    match started {
        Err(e) => {
            eprintln!("rea-agent: could not start pi: {e}");
            ExitCode::from(1)
        }
        Ok(status) if out.join("REPORT.md").is_file() => {
            println!("{}", out.join("REPORT.md").display());
            ExitCode::from(if status.success() { 0 } else { 3 })
        }
        Ok(status) => {
            eprintln!("rea-agent: pi exited ({status}) without REPORT.md; see {}", log.display());
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_run_with_model() {
        assert_eq!(
            parse(&args("run b.md --out o --model m")),
            Ok(Cli::Run { brief: "b.md".into(), out: "o".into(), model: Some("m".into()) })
        );
    }

    #[test]
    fn refuses_incomplete_or_unknown_input() {
        assert!(parse(&args("run b.md")).is_err());
        assert!(parse(&args("run --out o")).is_err());
        assert!(parse(&args("run b.md --out o --bogus")).is_err());
        assert!(parse(&args("run a.md b.md --out o")).is_err());
        assert!(parse(&args("check extra")).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn relative_out_becomes_absolute_so_pi_finds_the_role_from_inside_it() {
        let rel = PathBuf::from(format!("target/rel-out-test-{}", std::process::id()));
        let out = prepare_out(&rel).unwrap();
        assert!(out.is_absolute());
        assert_eq!(out, env::current_dir().unwrap().join(&rel));
        assert!(out.join("ROLE.md").is_file());
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn pi_gets_only_the_rea_skill_the_role_and_the_brief() {
        let a = pi_args(Path::new("S"), Path::new("R"), Path::new("B"), None);
        assert!(a.contains(&"--no-skills".to_string()));
        let at = |flag: &str| a[a.iter().position(|x| x == flag).unwrap() + 1].clone();
        assert_eq!(at("--skill"), "S");
        assert_eq!(at("--append-system-prompt"), "R");
        assert!(a.contains(&"@B".to_string()));
        assert!(!a.contains(&"--model".to_string()));
    }
}
