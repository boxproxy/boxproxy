use crate::Result;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Clone)]
pub struct Runner {
    dry_run: bool,
    verbose: bool,
}

pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Runner {
    pub fn new(dry_run: bool, verbose: bool) -> Self {
        Self { dry_run, verbose }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn run<S: AsRef<str>>(&self, program: &str, args: &[S]) -> Result<Output> {
        self.print_command(program, args);
        if self.dry_run {
            return Ok(Output {
                ok: false,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let output = Command::new(program)
            .args(args.iter().map(|value| value.as_ref()))
            .output()
            .map_err(|err| command_start_error("execute", program, err))?;

        Ok(Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    pub fn run_ok<S: AsRef<str>>(&self, program: &str, args: &[S]) -> bool {
        self.run(program, args)
            .map(|output| output.ok)
            .unwrap_or(false)
    }

    pub fn run_ignore<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        let _ = self.run(program, args);
    }

    pub fn signal(&self, pid: i32, sig: i32) {
        self.print_command("kill", &[format!("-{sig}"), pid.to_string()]);
        if self.dry_run {
            return;
        }
        send_signal(pid, sig);
    }

    pub fn preview<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        self.print_command(program, args);
    }

    pub fn run_with_stdin_output<S: AsRef<str>>(
        &self,
        program: &str,
        args: &[S],
        input: &str,
    ) -> Result<Output> {
        self.print_command(program, args);
        if self.verbose && !input.is_empty() {
            eprintln!("{input}");
        }
        if self.dry_run {
            return Ok(Output {
                ok: true,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let mut child = Command::new(program)
            .args(args.iter().map(|value| value.as_ref()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| command_start_error("execute", program, err))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(input.as_bytes())
                .map_err(|err| format!("write {program} stdin failed: {err}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|err| format!("wait for {program} failed: {err}"))?;

        Ok(Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    pub fn spawn_to_file_with_env_as<S: AsRef<str>>(
        &self,
        program: &str,
        args: &[S],
        log_path: &Path,
        envs: &[(&str, String)],
        uid: u32,
        gid: u32,
    ) -> Result<Option<u32>> {
        self.print_command(program, args);
        if self.dry_run {
            return Ok(None);
        }

        let stdout = File::create(log_path)
            .map_err(|err| format!("create log {} failed: {err}", log_path.display()))?;
        let stderr = stdout
            .try_clone()
            .map_err(|err| format!("copy log handle {} failed: {err}", log_path.display()))?;

        let mut command = Command::new(program);
        command
            .args(args.iter().map(|value| value.as_ref()))
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (key, value) in envs {
            command.env(*key, value.as_str());
        }
        apply_process_identity(&mut command, uid, gid);

        let child = command
            .spawn()
            .map_err(|err| command_start_error("start", program, err))?;

        Ok(Some(child.id()))
    }

    fn print_command<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        if self.dry_run || self.verbose {
            eprintln!("+ {}", shell_join(program, args));
        }
    }
}

#[cfg(unix)]
fn apply_process_identity(command: &mut Command, uid: u32, gid: u32) {
    command.uid(uid).gid(gid);
}

#[cfg(not(unix))]
fn apply_process_identity(_command: &mut Command, _uid: u32, _gid: u32) {}

#[cfg(unix)]
fn send_signal(pid: i32, sig: i32) {
    unsafe {
        kill(pid, sig);
    }
}

#[cfg(not(unix))]
fn send_signal(pid: i32, sig: i32) {
    let _ = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status();
}

fn command_start_error(action: &str, program: &str, err: io::Error) -> String {
    let diagnostics = executable_diagnostics(program);
    if diagnostics.is_empty() {
        format!("{action} {program} failed: {err}")
    } else {
        format!("{action} {program} failed: {err}; {diagnostics}")
    }
}

fn executable_diagnostics(program: &str) -> String {
    let path = Path::new(program);
    let mut parts = vec![format!("path={}", path.display())];
    match fs::metadata(path) {
        Ok(metadata) => {
            let kind = if metadata.is_file() {
                "file"
            } else if metadata.is_dir() {
                "dir"
            } else {
                "other"
            };
            parts.push(format!("type={kind}"));
            parts.push(format!("len={}", metadata.len()));
            parts.push(format!("readonly={}", metadata.permissions().readonly()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                parts.push(format!(
                    "mode={:o},uid={},gid={}",
                    metadata.mode() & 0o7777,
                    metadata.uid(),
                    metadata.gid()
                ));
            }
            if metadata.is_file() {
                if let Some(summary) = elf_summary(path) {
                    parts.push(summary);
                }
            }
        }
        Err(meta_err) => {
            parts.push(format!("metadata={meta_err}"));
        }
    }
    format!("diagnostics: {}", parts.join(", "))
}

fn elf_summary(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut header = [0_u8; 64];
    if file.read_exact(&mut header).is_err() {
        return Some("elf=unreadable-header".to_string());
    }
    if &header[0..4] != b"\x7fELF" {
        return Some(format!("magic={}", hex_prefix(&header, 8)));
    }

    let class = match header[4] {
        1 => "ELF32",
        2 => "ELF64",
        other => return Some(format!("elf=unknown-class-{other}")),
    };
    let little_endian = match header[5] {
        1 => true,
        2 => false,
        other => return Some(format!("elf={class}, endian=unknown-{other}")),
    };
    let machine = read_u16(&header[18..20], little_endian);
    let interpreter =
        elf_interpreter(&mut file, &header, little_endian).unwrap_or_else(|| "none".to_string());
    Some(format!(
        "elf={class},machine={machine},interpreter={interpreter}"
    ))
}

fn elf_interpreter(file: &mut File, header: &[u8; 64], little_endian: bool) -> Option<String> {
    const PT_INTERP: u32 = 3;
    let class = header[4];
    let (phoff, phentsize, phnum) = if class == 1 {
        (
            read_u32(&header[28..32], little_endian) as u64,
            read_u16(&header[42..44], little_endian) as u64,
            read_u16(&header[44..46], little_endian) as u64,
        )
    } else {
        (
            read_u64(&header[32..40], little_endian),
            read_u16(&header[54..56], little_endian) as u64,
            read_u16(&header[56..58], little_endian) as u64,
        )
    };
    if phoff == 0 || phentsize == 0 || phnum == 0 || phnum > 256 {
        return None;
    }

    for index in 0..phnum {
        let offset = phoff.checked_add(index.checked_mul(phentsize)?)?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut ph = vec![0_u8; phentsize as usize];
        file.read_exact(&mut ph).ok()?;
        let p_type = read_u32(ph.get(0..4)?, little_endian);
        if p_type != PT_INTERP {
            continue;
        }
        let (interp_offset, interp_size) = if class == 1 {
            (
                read_u32(ph.get(4..8)?, little_endian) as u64,
                read_u32(ph.get(16..20)?, little_endian) as u64,
            )
        } else {
            (
                read_u64(ph.get(8..16)?, little_endian),
                read_u64(ph.get(32..40)?, little_endian),
            )
        };
        return read_c_string_at(file, interp_offset, interp_size);
    }
    None
}

fn read_c_string_at(file: &mut File, offset: u64, size: u64) -> Option<String> {
    if size == 0 || size > 4096 {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = vec![0_u8; size as usize];
    file.read_exact(&mut bytes).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn read_u16(bytes: &[u8], little_endian: bool) -> u16 {
    let raw = [bytes[0], bytes[1]];
    if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    }
}

fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    }
}

fn read_u64(bytes: &[u8], little_endian: bool) -> u64 {
    let raw = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];
    if little_endian {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    }
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .take(len)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub(crate) fn shell_join<S: AsRef<str>>(program: &str, args: &[S]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_quote(program));
    parts.extend(args.iter().map(|arg| shell_quote(arg.as_ref())));
    parts.join(" ")
}

pub(crate) fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:@%+=".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
