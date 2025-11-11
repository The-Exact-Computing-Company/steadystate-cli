use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

mod helpers {
    use super::*;
    use serde_json::json;

    /// The mock HTTP responses used by the scripted server.
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
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Connection: close\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                }
                MockResponse::Unauthorized => {
                    "HTTP/1.1 401 Unauthorized\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\r\n"
                        .to_string()
                }
                MockResponse::Ok => {
                    "HTTP/1.1 200 OK\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\r\n"
                        .to_string()
                }
            }
        }
    }

    pub struct TestHarness {
        pub tempdir: TempDir,
        server_url: String,
        server_handle: Option<std::thread::JoinHandle<Vec<String>>>,
        shutdown_flag: Arc<AtomicBool>,
    }

    impl TestHarness {
        pub fn new(script: Vec<MockResponse>) -> Self {
            let tempdir = TempDir::new().expect("create tempdir");
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let (server_url, server_handle) = spawn_scripted_server(script, shutdown_flag.clone());
            Self {
                tempdir,
                server_url,
                server_handle: Some(server_handle),
                shutdown_flag,
            }
        }

        /// Runs the CLI once and asserts success.
        pub fn run_cli_and_assert(&mut self, args: &[&str]) -> (Output, Vec<String>) {
            let output = {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
                cmd.env("STEADYSTATE_CONFIG_DIR", self.tempdir.path());
                cmd.env("STEADYSTATE_BACKEND", &self.server_url);
                cmd.args(args);
                cmd.output().expect("run steadystate cli")
            };

            // Signal server to shut down
            self.shutdown_flag.store(true, Ordering::SeqCst);
            
            // Wait for server with timeout
            let start = Instant::now();
            let timeout = Duration::from_secs(5);
            let requests = loop {
                if let Some(handle) = self.server_handle.take() {
                    if handle.is_finished() {
                        break handle.join().unwrap();
                    }
                    
                    if start.elapsed() > timeout {
                        eprintln!("Server thread didn't finish within timeout, forcing shutdown");
                        // Try to connect to unblock the server
                        let _ = std::net::TcpStream::connect(&self.server_url.replace("http://", ""));
                        std::thread::sleep(Duration::from_millis(100));
                        
                        if handle.is_finished() {
                            break handle.join().unwrap();
                        } else {
                            panic!("Server thread stuck after timeout");
                        }
                    }
                    
                    self.server_handle = Some(handle);
                    std::thread::sleep(Duration::from_millis(50));
                } else {
                    panic!("Server handle already consumed");
                }
            };

            if !output.status.success() {
                eprintln!("=== CLI STDOUT ===\n{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("=== CLI STDERR ===\n{}", String::from_utf8_lossy(&output.stderr));
                eprintln!("=== SERVER REQUESTS ===");
                for (i, req) in requests.iter().enumerate() {
                    eprintln!("--- Request {} ---\n{}\n", i, req);
                }
                panic!("CLI failed unexpectedly");
            }

            (output, requests)
        }

        pub fn create_session(&self, login: &str, jwt: &str, jwt_exp: Option<u64>) {
            let dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("session.json");
            let session = json!({ "login": login, "jwt": jwt, "jwt_exp": jwt_exp });
            fs::write(path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();
        }

        pub fn create_future_session(&self) {
            let exp = now() + 3600;
            self.create_session("tester", "test-jwt", Some(exp));
        }

        pub fn create_expired_session(&self) {
            let exp = now() - 10;
            self.create_session("tester", "expired-jwt", Some(exp));
        }

        pub fn set_keyring_password(&self, username: &str, password: &str) {
            keyring::Entry::new("steadystate", username)
                .unwrap()
                .set_password(password)
                .unwrap();
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            // Ensure shutdown on drop
            self.shutdown_flag.store(true, Ordering::SeqCst);
            
            // Try to unblock server if still running
            if let Some(handle) = self.server_handle.take() {
                if !handle.is_finished() {
                    let _ = std::net::TcpStream::connect(&self.server_url.replace("http://", ""));
                    let _ = handle.join();
                }
            }
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Minimal HTTP/1.1 scripted server with shutdown support
    pub fn spawn_scripted_server(
        responses: Vec<MockResponse>,
        shutdown: Arc<AtomicBool>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut reqs = Vec::new();
            let mut response_iter = responses.into_iter();
            
            'outer: loop {
                // Check shutdown flag
                if shutdown.load(Ordering::SeqCst) && response_iter.len() == 0 {
                    break;
                }
                
                // Try to accept connection with timeout
                let (mut stream, _) = match listener.accept() {
                    Ok(conn) => conn,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        
                        // If we've processed all responses and shutdown is requested, exit
                        if shutdown.load(Ordering::SeqCst) && response_iter.len() == 0 {
                            break 'outer;
                        }
                        continue;
                    }
                    Err(e) => panic!("accept error: {e:?}"),
                };
                
                // Get next response, or break if we're done
                let response = match response_iter.next() {
                    Some(r) => r,
                    None => {
                        drop(stream);
                        break;
                    }
                };

                stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                stream.set_write_timeout(Some(Duration::from_millis(500))).unwrap();

                let mut buf = Vec::new();
                let start = Instant::now();
                loop {
                    if start.elapsed() > Duration::from_secs(2) {
                        eprintln!("Warning: request read timeout");
                        break;
                    }
                    
                    let mut chunk = [0u8; 1024];
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            // Look for end of headers
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock 
                               || e.kind() == std::io::ErrorKind::TimedOut => {
                            if buf.len() > 0 {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => {
                            eprintln!("read error: {e:?}");
                            break;
                        }
                    }
                }

                reqs.push(String::from_utf8_lossy(&buf).to_string());
                let resp = response.into_http_string();
                let _ = stream.write_all(resp.as_bytes());
            }
            reqs
        });

        (format!("http://{}", addr), handle)
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
        MockResponse::Unauthorized,
        MockResponse::Json(json!({ "jwt": "new-jwt-123" })),
        MockResponse::Json(json!({ "id": "session-999", "ssh_url": "ssh://after-refresh" })),
    ];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-abc");

    let (out, reqs) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(reqs.len(), 3);
    assert!(reqs[0].starts_with("POST /sessions"));
    assert!(reqs[1].starts_with("POST /auth/refresh"));
    assert!(reqs[2].starts_with("POST /sessions"));

    let stdout = String::from_utf8(out.stdout).unwrap();
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

    let (_, reqs) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(reqs.len(), 2);
    assert!(reqs[0].starts_with("POST /auth/refresh"));
    assert!(reqs[1].starts_with("POST /sessions"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let script = vec![MockResponse::Ok];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-to-revoke");

    let (_, reqs) = harness.run_cli_and_assert(&["logout"]);

    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].starts_with("POST /auth/revoke"));

    let json = harness.tempdir.path().join("steadystate/session.json");
    assert!(!json.exists());

    let res = keyring::Entry::new("steadystate", "tester").unwrap().get_password();
    assert!(res.is_err());
}
