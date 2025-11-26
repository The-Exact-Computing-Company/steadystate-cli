use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use yrs::{Doc, Text, Transact, GetString};
use similar::{ChangeTag, TextDiff};
use walkdir::WalkDir;

pub type FilePath = String;
pub type FileContent = Vec<u8>;

#[derive(Debug, Clone)]
pub struct TreeSnapshot {
    pub files: HashMap<FilePath, FileContent>,
}

impl TreeSnapshot {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<&FileContent> {
        self.files.get(path)
    }
}

/// Materialize a tree from a Git commit in a repository.
pub fn materialize_git_tree(repo_path: &Path, commit_hash: &str) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot::new();

    // 1. List all files in the commit
    // git ls-tree -r --name-only <commit>
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["ls-tree", "-r", "--name-only", commit_hash])
        .output()
        .context("Failed to run git ls-tree")?;

    if !output.status.success() {
        return Err(anyhow!("git ls-tree failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = stdout.lines().collect();

    // 2. Read content for each file
    // Optimization: Use git cat-file --batch for larger repos, but loop is fine for MVP
    for file_path in files {
        if file_path.trim().is_empty() {
            continue;
        }

        let content_output = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(&["show", &format!("{}:{}", commit_hash, file_path)])
            .output()
            .context(format!("Failed to read file {} from git", file_path))?;

        if content_output.status.success() {
            snapshot.files.insert(file_path.to_string(), content_output.stdout);
        }
    }

    Ok(snapshot)
}

/// Materialize a tree from the filesystem (worktree).
pub fn materialize_fs_tree(root_path: &Path) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot::new();

    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        
        // Skip .git, .worktree, etc.
        let rel_path = path.strip_prefix(root_path)?;
        let rel_path_str = rel_path.to_string_lossy();

        if rel_path_str.starts_with(".git") || rel_path_str.starts_with(".worktree") || rel_path_str.contains("/.git/") {
            continue;
        }

        let content = std::fs::read(path)?;
        snapshot.files.insert(rel_path_str.to_string(), content);
    }

    Ok(snapshot)
}

/// Merge three trees using Yjs CRDT logic.
pub fn merge_trees(
    base: &TreeSnapshot,
    local: &TreeSnapshot,
    canonical: &TreeSnapshot,
) -> Result<TreeSnapshot> {
    let mut merged = TreeSnapshot::new();

    // Union of all file paths
    let mut all_files = HashSet::new();
    all_files.extend(base.files.keys());
    all_files.extend(local.files.keys());
    all_files.extend(canonical.files.keys());

    for path in all_files {
        let base_content = base.files.get(path);
        let local_content = local.files.get(path);
        let canon_content = canonical.files.get(path);

        // Handle binary/text distinction
        // For now, assume everything is text if it's valid UTF-8
        // If any side is binary, fallback to "canonical wins" or "local wins" logic?
        // Design doc: "If file is binary: If only one side changed -> take that. If both -> prefer canonical."

        let base_s = base_content.and_then(|c| String::from_utf8(c.clone()).ok());
        let local_s = local_content.and_then(|c| String::from_utf8(c.clone()).ok());
        let canon_s = canon_content.and_then(|c| String::from_utf8(c.clone()).ok());

        if let (Some(b), Some(l), Some(c)) = (&base_s, &local_s, &canon_s) {
            // All three are text -> CRDT merge
            let merged_text = merge_file_yjs(b, l, c)?;
            merged.files.insert(path.clone(), merged_text.into_bytes());
        } else {
            // Binary or mixed or deleted
            
            let b_text = base_s.clone().unwrap_or_default();
            let l_text = local_s.clone().unwrap_or_default();
            let c_text = canon_s.clone().unwrap_or_default();
            
            // Check if they were actually text files (valid UTF-8)
            // If any existing content was NOT utf-8, treat as binary.
            let is_binary = (base_content.is_some() && base_s.is_none()) ||
                            (local_content.is_some() && local_s.is_none()) ||
                            (canon_content.is_some() && canon_s.is_none());

            if is_binary {
                // Binary merge strategy
                let empty_vec = vec![];
                let base_bytes = base_content.unwrap_or(&empty_vec);
                let local_bytes = local_content.unwrap_or(&empty_vec);
                let canon_bytes = canon_content.unwrap_or(&empty_vec);

                if local_bytes != base_bytes && canon_bytes == base_bytes {
                    // Only local changed
                    if local_content.is_some() {
                        merged.files.insert(path.clone(), local_bytes.clone());
                    }
                } else if canon_bytes != base_bytes && local_bytes == base_bytes {
                    // Only canonical changed
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes.clone());
                    }
                } else {
                    // Both changed or identical
                    // Prefer canonical
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes.clone());
                    }
                }
            } else {
                // Text merge (handling deletions as empty strings)
                // If all are None, skip
                if base_content.is_none() && local_content.is_none() && canon_content.is_none() {
                    continue;
                }
                
                // If local deleted and canonical deleted -> deleted
                if local_content.is_none() && canon_content.is_none() {
                    continue;
                }

                let merged_text = merge_file_yjs(&b_text, &l_text, &c_text)?;
                
                merged.files.insert(path.clone(), merged_text.into_bytes());
            }
        }
    }

    Ok(merged)
}

/// Perform a 3-way merge of text using Yrs.
pub fn merge_file_yjs(base: &str, local: &str, canonical: &str) -> Result<String> {
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::Encode;
    use yrs::ReadTxn;

    // Helper to apply diffs to a doc initialized with base
    let apply_diff = |target: &str| -> Result<Vec<u8>> {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("content");
        
        // Init with base
        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, base);
        }
        
        // Apply changes
        {
            let mut txn = doc.transact_mut();
            let diff = TextDiff::from_chars(base, target);
            let mut pos = 0;
            
            for change in diff.iter_all_changes() {
                match change.tag() {
                    ChangeTag::Equal => {
                        pos += change.value().chars().count() as u32;
                    }
                    ChangeTag::Delete => {
                        let len = change.value().chars().count() as u32;
                        text.remove_range(&mut txn, pos, len);
                    }
                    ChangeTag::Insert => {
                        text.insert(&mut txn, pos, change.value());
                        pos += change.value().chars().count() as u32;
                    }
                }
            }
        }
        
        // Encode state
        let update = doc.transact().encode_state_as_update_v1(&yrs::StateVector::default());
        Ok(update)
    };

    let local_update = apply_diff(local)?;
    let canonical_update = apply_diff(canonical)?;

    // Merge into a fresh doc
    let doc = Doc::new();
    let text = doc.get_or_insert_text("content");
    
    // Init with base (so updates apply correctly?)
    // Actually, if we apply updates to a doc that already has base, it might duplicate?
    // Yjs updates contain the full history or deltas?
    // If I created two docs starting from scratch (empty) -> insert base -> apply diffs.
    // Then their updates contain "insert base" + "diffs".
    // If I merge them, "insert base" might be deduplicated if they have same ClientID?
    // No, different docs have different ClientIDs by default.
    // So "insert base" would be duplicated! "BaseBase..."
    
    // We need to ensure "insert base" has the SAME ID in both docs.
    // We can do this by setting a fixed ClientID for the "base" operation?
    // Or simpler:
    // 1. Create `doc`. Insert `base`.
    // 2. `doc_local` = fork `doc`. Apply local.
    // 3. `doc_remote` = fork `doc`. Apply remote.
    // 4. Merge updates from `doc_local` and `doc_remote` back to `doc`.
    
    // Yrs doesn't have "fork".
    // But we can encode the state of `doc` (with base) and load it into `doc_local` and `doc_remote`.
    
    let doc_base = Doc::new();
    let text_base = doc_base.get_or_insert_text("content");
    {
        let mut txn = doc_base.transact_mut();
        text_base.insert(&mut txn, 0, base);
    }
    let base_state = doc_base.transact().encode_state_as_update_v1(&yrs::StateVector::default());

    let apply_diff_on_base = |target: &str| -> Result<Vec<u8>> {
        let doc = Doc::new();
        // Load base state
        {
            let mut txn = doc.transact_mut();
            let update = yrs::Update::decode_v1(&base_state).context("Failed to decode base state")?;
            txn.apply_update(update);
        }
        
        let text = doc.get_or_insert_text("content");
        
        // Apply changes
        {
            let mut txn = doc.transact_mut();
            let diff = TextDiff::from_chars(base, target);
            let mut pos = 0;
            
            for change in diff.iter_all_changes() {
                match change.tag() {
                    ChangeTag::Equal => {
                        pos += change.value().chars().count() as u32;
                    }
                    ChangeTag::Delete => {
                        let len = change.value().chars().count() as u32;
                        text.remove_range(&mut txn, pos, len);
                    }
                    ChangeTag::Insert => {
                        text.insert(&mut txn, pos, change.value());
                        pos += change.value().chars().count() as u32;
                    }
                }
            }
        }
        
        // Return update delta from base
        // We want the update that represents the *changes* made on top of base.
        // encode_state_as_update_v1 returns everything.
        // But since we started with same base (same ClientIDs for base ops), merging them should deduplicate base.
        let update = doc.transact().encode_state_as_update_v1(&yrs::StateVector::default());
        Ok(update)
    };

    let local_update = apply_diff_on_base(local)?;
    let canonical_update = apply_diff_on_base(canonical)?;

    // Merge
    let doc_final = Doc::new();
    let text_final = doc_final.get_or_insert_text("content");
    {
        let mut txn = doc_final.transact_mut();
        // Apply local
        let up_l = yrs::Update::decode_v1(&local_update)?;
        txn.apply_update(up_l);
        
        // Apply canonical
        let up_c = yrs::Update::decode_v1(&canonical_update)?;
        txn.apply_update(up_c);
    }

    let result = text_final.get_string(&doc_final.transact());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_no_conflict() {
        let base = "Hello World";
        let local = "Hello World!";
        let remote = "Hello World";
        let merged = merge_file_yjs(base, local, remote).unwrap();
        assert_eq!(merged, "Hello World!");
    }

    #[test]
    fn test_merge_non_conflicting() {
        let base = "Hello World";
        let local = "Hello World!";
        let remote = "Hello World?";
        let merged = merge_file_yjs(base, local, remote).unwrap();
        // Order depends on Yjs internals but should contain both
        assert!(merged.contains("!"));
        assert!(merged.contains("?"));
    }

    #[test]
    fn test_merge_deletion() {
        let base = "Hello World";
        let local = "Hello";
        let remote = "Hello World";
        let merged = merge_file_yjs(base, local, remote).unwrap();
        assert_eq!(merged, "Hello");
    }

    #[test]
    fn test_merge_concurrent_insert() {
        let base = "";
        let local = "A";
        let remote = "B";
        let merged = merge_file_yjs(base, local, remote).unwrap();
        assert!(merged == "AB" || merged == "BA");
    }
    
    #[test]
    fn test_merge_mixed_edit() {
        let base = "Line1\nLine2\nLine3";
        let local = "Line1\nLine2 Modified\nLine3";
        let remote = "Line1\nLine2\nLine3 Modified";
        let merged = merge_file_yjs(base, local, remote).unwrap();
        assert!(merged.contains("Line2 Modified"));
        assert!(merged.contains("Line3 Modified"));
    }
}
