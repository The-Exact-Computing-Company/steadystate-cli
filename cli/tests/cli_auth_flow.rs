use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

// =============================
// Utility helpers
// =============================

fn write_session(path: &TempDir, login: &str, jwt: &str, jwt_exp: Option<u64>) {
    let dir = path.path().join("steadystate");
    fs::create_dir_all(&dir).unwrap();
    let sess_path = dir.join("session.json");
    let sess = serde_json::json!({
        "login": login,
        "jwt": jwt,
        "jwt_exp": jwt_exp
    });
    fs::write(sess_path, serde_json::to_vec_pretty(&sess).unwrap()).unwrap();
}

fn run_cli(path: Option<&TempDir>, envs: &[(&str, String)], args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_steadystate"));
    if let Some(p) = path {
        cmd.env("STEADYSTATE_CONFIG_DIR", p.path());
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args(args);
    cmd.output().expect("run cli")
}

// =============================
// Mock Server
// =============================

fn read_full_request(stream: &mut TcpStream) -> String {
    let mut buf = [0u8; 4096];
    let mut out = Vec::new();
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .unwrap();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

struct MockServer {
    addr: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockServer {
    fn new<F>(handler: F) -> Self
    where
        F: Fn(String, &mut TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(listener);

        let listener_thread = Arc::clone(&listener);

        let handle = std::thread::spawn(move || {
            for incoming in listener_thread.incoming() {
                match incoming {
                    Ok(mut stream) => {
                        let req = read_full_request(&mut stream);
                        handler(req, &mut stream);
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr: format!("http://{}", addr),
            handle: Some(handle),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        // Shutdown listener instantly so tests never block
        let _ = TcpStream::connect(self.addr.replace("http://", ""));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// =============================
// TESTS
// =============================

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let td = TempDir::new().unwrap();

    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH"]);
    assert!(setup.status.success());

    write_session(&td, "me", "OLD_JWT", Some(5_000_000_000));

    let call_counter = Arc::new(AtomicUsize::new(0));

    let mock = MockServer::new({
        let call_counter = Arc::clone(&call_counter);
        move |req, stream| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            match call {
                0 => {
                    assert!(req.starts_with("POST /sessions"));
                    assert!(req.to_lowercase().contains("bearer old_jwt"));
                    stream
                        .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
                1 => {
                    assert!(req.starts_with("POST /auth/refresh"));
                    let body = r#"{"jwt":"NEW_JWT"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                2 => {
                    assert!(req.starts_with("POST /sessions"));
                    assert!(req.to_lowercase().contains("bearer new_jwt"));
                    let body = r#"{"id":"abc","ssh_url":"ssh://ok"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                _ => panic!("Unexpected call"),
            }
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock.addr.clone())],
        &["up", "https://github.com/x/y"],
    );

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("✅ Session created"));
}

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let td = TempDir::new().unwrap();

    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH"]);
    assert!(setup.status.success());

    let expired = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;

    write_session(&td, "me", "EXPIRED_JWT", Some(expired));

    let call_counter = Arc::new(AtomicUsize::new(0));

    let mock = MockServer::new({
        let call_counter = Arc::clone(&call_counter);
        move |req, stream| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            match call {
                0 => {
                    assert!(req.starts_with("POST /auth/refresh"));
                    let body = r#"{"jwt":"FRESH"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                1 => {
                    assert!(req.starts_with("POST /sessions"));
                    assert!(req.to_lowercase().contains("bearer fresh"));
                    let body = r#"{"id":"abc","ssh_url":"ssh://ok"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                _ => panic!("Unexpected call"),
            }
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock.addr.clone())],
        &["up", "https://github.com/x/y"],
    );

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("✅ Session created"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let td = TempDir::new().unwrap();

    write_session(&td, "me", "jwt", Some(5_000_000_000));
    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH"]);
    assert!(setup.status.success());

    let mock = MockServer::new(|req, stream| {
        assert!(req.starts_with("POST /auth/revoke"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock.addr.clone())],
        &["logout"],
    );

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Logged out"));
    assert!(!td.path().join("steadystate/session.json").exists());
}
