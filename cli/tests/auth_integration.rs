use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::TempDir;

// Using a module to encapsulate all the test infrastructure.
mod helpers {
    use super::*;
    use serde_json::json;
    use std::net::TcpStream;

    /// Scripted responses from the mock server.
    pub enum MockResponse {
        Json(serde_json::Value),
        Unauthorized,
        Ok,
    }

    impl MockResponse {
        fn into_http_string(self) -> String {
            match self {
                MockResponse::Json(val) => {
                    let body = serde_json::to_string(&val).unwrap();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                }
                MockResponse::Unauthorized => {
                    "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                }
                MockResponse::Ok => {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
                }
            }
        }
    }

    /// Manages the environment for one integration test.
    pub struct TestHarness {
        pub tempdir: TempDir,
        server_url: String,
        server_handle: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl TestHarness {
        pub fn new(script: Vec<MockResponse>) -> Self {
            let tempdir = TempDir::new().expect("create tempdir");
            let (server_url, server_handle) = spawn_scripted_server(script);
            Self {
                tempdir,
                server_url,
                server_handle: Some(server_handle),
            }
        }

        /// Run CLI once; returns output and captured requests.
        pub fn run_cli_and_assert(&mut self, args: &[&str]) -> (Output, Vec<String>) {
            let output = {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
                cmd.env("STEADYSTATE_CONFIG_DIR", self.tempdir.path());
                cmd.env("STEADYSTATE_BACKEND", &self.server_url);
                cmd.args(args);
                cmd.output().expect("run steadystate cli")
            };

            let requests = self.server_handle.take().unwrap().join().unwrap();

            if !output.status.success() {
                eprintln!("=== CLI STDOUT ===\n{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("=== CLI STDERR ===\n{}", String::from_utf8_lossy(&output.stderr));
                eprintln!("=== SERVER REQUESTS ===");
                for (i, r) in requests.iter().enumerate() {
                    eprintln!("--- Request {} ---\n{}\n", i, r);
                }
                panic!("CLI failed unexpectedly");
            }

            (output, requests)
        }

        pub fn create_session(&self, login: &str, jwt: &str, jwt_exp: Option<u64>) {
            let service_dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&service_dir).expect("create service dir");
            let session_path = service_dir.join("session.json");
            let session = json!({ "login": login, "jwt": jwt, "jwt_exp": jwt_exp });
            fs::write(&session_path, serde_json::to_vec_pretty(&session).unwrap())
                .expect("write session file");
        }

        pub fn create_future_session(&self) {
            let future = std::time::SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "test-jwt", Some(future));
        }

        pub fn create_expired_session(&self) {
            let expired = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "expired-jwt", Some(expired));
        }

        pub fn set_keyring_password(&self, username: &str, password: &str) {
            keyring::Entry::new("steadystate", username)
                .unwrap()
                .set_password(password)
                .unwrap();
        }
    }

    /// Spawn a scripted HTTP/1.1 server that handles `Expect: 100-continue`.
    fn spawn_scripted_server(
        responses: Vec<MockResponse>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted server");
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();

            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");
                // Avoid infinite hangs in CI
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

                // 1) read headers
                let (raw_request, content_length, expect_continue) =
                    read_headers_return_len_and_expect(&mut stream).expect("read headers");

                requests.push(raw_request.clone());

                // 2) If Expect: 100-continue, send interim response now
                if expect_continue {
                    let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                }

                // 3) read exactly content_length bytes of body (if any)
                if content_length > 0 {
                    read_exact_body(&mut stream, content_length).expect("read body");
                }

                // 4) write the scripted final response
                let reply = response.into_http_string();
                stream.write_all(reply.as_bytes()).unwrap();

                // 5) Close this connection (Connection: close semantics)
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }

            requests
        });

        (format!("http://{}", addr), handle)
    }

    /// Read until CRLFCRLF; parse Content-Length and Expect headers.
    fn read_headers_return_len_and_expect(
        stream: &mut TcpStream,
    ) -> std::io::Result<(String, usize, bool)> {
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..n]);
            if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let header_end = buffer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no header end"))?;
        let headers_bytes = &buffer[..header_end + 4];
        let headers_str = std::str::from_utf8(headers_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "utf8"))?;

        let mut content_length = 0usize;
        let mut expect_continue = false;

        for line in headers_str.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if name.eq_ignore_ascii_case("Content-Length") {
                    if let Ok(v) = value.parse::<usize>() {
                        content_length = v;
                    }
                } else if name.eq_ignore_ascii_case("Expect") {
                    if value.eq_ignore_ascii_case("100-continue") {
                        expect_continue = true;
                    }
                }
            }
        }

        Ok((String::from_utf8_lossy(headers_bytes).to_string(), content_length, expect_continue))
    }

    fn read_exact_body(stream: &mut TcpStream, len: usize) -> std::io::Result<()> {
        let mut remaining = len;
        let mut buf = [0u8; 4096];
        while remaining > 0 {
            let to_read = remaining.min(buf.len());
            let n = stream.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof while reading body",
                ));
            }
            remaining -= n;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

use helpers::{MockResponse, TestHarness};
use serde_json::json;

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let script = vec![
        // 1) First POST /sessions => 401 triggers refresh
        MockResponse::Unauthorized,
        // 2) POST /auth/refresh => 200 with new jwt
        MockResponse::Json(json!({ "jwt": "new-jwt-123" })),
        // 3) Second POST /sessions => 200 success
        MockResponse::Json(json!({ "id": "session-999", "ssh_url": "ssh://after-refresh" })),
    ];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-abc");

    let (output, requests) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST /sessions"));
    assert!(requests[1].starts_with("POST /auth/refresh"));
    assert!(requests[2].starts_with("POST /sessions"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("session-999"));
}

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let script = vec![
        MockResponse::Json(json!({ "jwt": "fresh-jwt-321" })),
        MockResponse::Json(json!({ "id": "session-expired", "ssh_url": "ssh://expired.example" })),
    ];
    let mut harness = TestHarness::new(script);
    harness.create_expired_session();
    harness.set_keyring_password("tester", "refresh-token-xyz");

    let (_, requests) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /auth/refresh"));
    assert!(requests[1].starts_with("POST /sessions"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let script = vec![MockResponse::Ok];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-to-revoke");

    let (_, requests) = harness.run_cli_and_assert(&["logout"]);

    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /auth/revoke"));

    // Session file removed
    let session_path = harness.tempdir.path().join("steadystate/session.json");
    assert!(!session_path.exists(), "Session file was not removed");

    // Keychain token removed
    let res = keyring::Entry::new("steadystate", "tester").unwrap().get_password();
    assert!(res.is_err(), "Keyring entry was not removed");
}
