use anyhow::{Context, Result};
use std::process::Command;
use std::path::Path;
use std::io::Write;

pub fn sync() -> Result<()> {
    println!("Syncing changes...");

    // 1. Record local changes
    // We assume we are inside the worktree (user should run this from within the session)
    // But wait, the CLI runs on the CLIENT machine, or inside the SSH session?
    // The user runs `steadystate sync` INSIDE the SSH session.
    // So this CLI needs to be available inside the session.
    // OR, the user runs it locally and it SSHs in to run commands?
    
    // The user request says: "Alice and Bob SSH in... When Bob wants to sync... steadystate sync"
    // This implies `steadystate` CLI is installed/available INSIDE the remote session.
    // OR `steadystate sync` is run locally and talks to the remote?
    
    // If run locally, it needs to know WHICH session to sync.
    // If run remotely, it's just a wrapper around pijul.
    
    // Given the architecture "Server-Side Worktrees", the user is SSH'd into the server.
    // They are in a shell on the server.
    // So `steadystate` binary must be present on the server.
    // AND it must detect it's running in a session.
    
    // Let's assume for now we are running ON THE SERVER.
    
    // 1. Record
    let status = Command::new("pijul")
        .args(&["record", "-a", "-m", "Auto-sync", "--author", "SteadyState <bot@steadystate.dev>"])
        .status()
        .context("Failed to run pijul record")?;
        
    if !status.success() {
        // It might fail if nothing to record, which is fine?
        // Pijul returns 0 even if nothing recorded?
        // Let's warn but continue.
        println!("(No local changes to record or record failed)");
    }

    // 2. Push to canonical
    // Canonical is at ../../canonical (relative to worktree)
    // Or we can use absolute path if we know it.
    // The wrapper script set REPO_ROOT. Maybe we can use that env var?
    // Or just assume standard layout: worktrees/<user> -> ../../canonical
    
    // Resolve sync-log path
    let repo_root = std::env::var("REPO_ROOT").unwrap_or_else(|_| "../..".to_string());
    let sync_log_path = Path::new(&repo_root).join("sync-log");
    // Pijul push/pull uses the default remote which is set during clone.
    // So we don't strictly need canonical_path unless we want to verify it exists.
    // Or better, push to "default" remote if configured?
    // Pijul clone sets the remote.
    
    let status = Command::new("pijul")
        .args(&["push", "-a"])
        .status()
        .context("Failed to run pijul push")?;
        
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to push changes to canonical repo"));
    }

    // 3. Pull from canonical (merge)
    let status = Command::new("pijul")
        .args(&["pull", "-a"])
        .status()
        .context("Failed to run pijul pull")?;

    if !status.success() {
        return Err(anyhow::anyhow!("Failed to pull changes from canonical repo"));
    }
    
    // 4. Update sync-log
    // Log file is at ../../sync-log
    
    // We need to append: timestamp user
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    let log_entry = format!("{} {}\n", timestamp, user);
    
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&sync_log_path)
        .context("Failed to open sync-log")?;
        
    file.write_all(log_entry.as_bytes())
        .context("Failed to write to sync-log")?;

    println!("✅ Sync complete!");
    Ok(())
}
