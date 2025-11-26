# Y-CRDT Merge Engine for SteadyState (Phase 2)

**Goal:**
SteadyState should perform merges using CRDT semantics (Yjs/Yrs), generating a conflict-free merged tree for the canonical Git repo—no Pijul, no Git conflicts, no textual merging.

This is the core of the new architecture.

## 2.1 Core model: three trees

For each `steadystate sync`, you have:

### 1. canonical_tree

The Git tree at **HEAD** in the canonical repo.

### 2. local_tree

The user’s ephemeral worktree as it currently exists on disk.

### 3. base_tree

The canonical tree at the moment the user’s worktree was last synchronized.

`base_tree` is stored in:

```json
// .worktree/steadystate.json
{
  "last_synced_commit": "<hash>"
}
```

This gives us the required structure for a three-way merge:

```
merge(base_tree, local_tree, canonical_tree) → merged_tree
```

We do *not* use a multi-file delta; instead we do per-file Yjs merges.

## 2.2 Representing each file as a Yjs document

For each file (text files only; skip binaries for now):

* Read:
  * `base_text` from `base_tree/file`
  * `local_text` from `local_tree/file`
  * `canonical_text` from `canonical_tree/file`

* Create a new Yjs/Yrs `YDoc`.

* Insert `base_text` into a `YText` inside the doc.

* Compute operations:

```
ops_local     = diff(base_text → local_text)
ops_canonical = diff(base_text → canonical_text)
```

Use any standard line-based or char-based diff algorithm (you already have one in the codebase; alternatively use `diffy`, `similar`, or `xi-unicode`).

* Apply ops to the YText sequentially:

```rust
let ydoc = yrs::Doc::new();
let ytext = ydoc.get_or_insert_text("content");

ytext.insert(0, &base_text);

// Apply local deltas
for op in ops_local { ytext.apply_delta(op); }

// Apply remote deltas
for op in ops_canonical { ytext.apply_delta(op); }
```

Yjs/Yrs guarantees:
* convergence,
* no conflicts,
* deterministic final state no matter the order of ops.

* Serialize merged text:

```rust
let merged_text = ytext.to_string();
```

* Write to `merged_tree/file`.

## 2.3 Managing file sets

You need a unified file list. Define:

```
files = union of:
    files(base_tree)
    ∪ files(local_tree)
    ∪ files(canonical_tree)
```

For each file:
* if exists in all three → 3-way Yjs merge
* if deleted in local but present in canonical → treat empty local as `""`
* if deleted in canonical but present in local → treat empty canonical as `""`
* if created locally → base = "", canonical = current
* if created in canonical → base = "", local = current

Yjs handles these without conflict.

## 2.4 Materializing the three trees

### In canonical repo:

```bash
git show <base_commit>:<path>  # for base_tree
git show HEAD:<path>           # for canonical_tree
```

### In user worktree:

Just read from disk, skipping `.git/` and `.worktree/`.

### Temporary dirs:

```
/tmp/steadystate/base
/tmp/steadystate/local
/tmp/steadystate/remote
/tmp/steadystate/merged
```

## 2.5 Writing merged_tree back into canonical Git

After the Yjs/Yrs merge loop finishes:

1. Copy `merged_tree/*` into canonical worktree (overwriting).
2. In canonical repo:

```bash
git add -A
git commit -m "sync: SteadyState session $SESSION_ID by $USER"
git push origin HEAD
```

If `git diff --cached --quiet` is true → skip commit.

## 2.6 Refresh the user’s worktree

After canonical is updated:

```bash
git fetch origin
git reset --hard origin/HEAD
```

or simply remove and re-clone for simplicity and correctness.

## 2.7 Update metadata

Write the new canonical commit hash:

```
last_synced_commit = git rev-parse HEAD
```

and update `.worktree/steadystate.json`.

## 2.8 Modify CLI sync.rs

Replace the old Pijul logic with:

1. Identify paths (you already do this).
2. Materialize `base_tree`.
3. Materialize `local_tree`.
4. Materialize `canonical_tree`.
5. Do Yrs per-file merges.
6. Produce merged_tree.
7. Apply merged_tree to canonical Git repo.
8. Commit & push.
9. Reset user worktree.
10. Log to sync-log (existing behavior kept).

No Pijul commands remain.

## 2.9 Detailed Rust pseudocode for engineers

```rust
fn sync() -> Result<()> {
    // 1. Determine paths
    let root = find_repo_root()?;
    let canonical = root.join("canonical");
    let worktree = std::env::current_dir()?;
    let meta_path = worktree.join(".worktree/steadystate.json");

    // 2. Load base commit
    let base_commit = read_base_commit(&meta_path)
        .unwrap_or_else(|| current_canonical_head(&canonical));

    // 3. Materialize tree snapshots
    let base_tree     = materialize_tree(&canonical, base_commit)?;
    let canonical_tree = materialize_tree(&canonical, "HEAD")?;
    let local_tree     = materialize_local_tree(&worktree)?;

    // 4. Compute file union
    let files = union_files(&base_tree, &local_tree, &canonical_tree);

    // 5. Merge each file via Yrs
    let mut merged_tree = HashMap::new();
    for file in files {
        let base_text     = base_tree.get(&file).unwrap_or("").to_owned();
        let local_text    = local_tree.get(&file).unwrap_or("").to_owned();
        let canonical_text = canonical_tree.get(&file).unwrap_or("").to_owned();

        let merged = merge_file_yjs(&base_text, &local_text, &canonical_text)?;
        merged_tree.insert(file, merged);
    }

    // 6. Write merged result back into canonical repo
    write_merged_into_canonical(&canonical, &merged_tree)?;

    // 7. Commit + push
    git_commit_and_push(&canonical)?;

    // 8. Reset user worktree to canonical HEAD
    refresh_user_worktree(&worktree, &canonical)?;

    // 9. Update metadata
    write_base_commit(&meta_path, canonical_head(&canonical));

    // 10. Log
    append_sync_log(&worktree)?;

    Ok(())
}
```

## 2.10 CRDT invariants for engineers

### Yjs guarantees:
* no conflicts
* associativity
* commutativity
* idempotence
* deterministic convergence

Therefore:
* Diff quality does *not* affect correctness, only efficiency.
* Order of applying local and canonical ops doesn’t matter.
* The system is robust to partial writes and replays.

## 2.11 No running Yjs server required

You are **not** building a real-time collaborative editor server.
Yjs/Yrs is used purely as a **merge engine**.

Meaning:
* No awareness of clients.
* No websockets.
* No provider.
* Just two deltas → one merged document.

This keeps complexity low and makes sync deterministic.
