# NAME

**steadystate merge engine** - conflict-free 3-way merge algorithm

# SYNOPSIS

```
merge_trees(base, local, canonical) → merged
merge_file_yjs(base_text, local_text, canonical_text) → merged_text
```

# DESCRIPTION

SteadyState uses a custom 3-way merge algorithm based on Longest Common Subsequence (LCS) to automatically merge concurrent edits from multiple collaborators without conflicts.

The merge engine operates at two levels:

1. **Tree-level** - Determines which files changed and how to handle them
2. **File-level** - Merges text content using token-based LCS

# THE THREE TREES

Every sync operation works with three trees:

```
            Base Tree
           (last sync)
              /   \
             /     \
      Local Tree   Canonical Tree
      (worktree)   (remote HEAD)
             \     /
              \   /
           Merged Tree
```

## Base Tree

The state of the repository at the user's last sync point. Stored in:

```json
// .worktree/steadystate.json
{
  "session_branch": "steadystate/abc123",
  "last_synced_commit": "a1b2c3d..."
}
```

Materialized using:

```bash
git show <last_synced_commit>:<file>
```

## Local Tree

The current state of the user's worktree on disk. Read directly from the filesystem, excluding `.git/` and `.worktree/` directories.

## Canonical Tree

The current HEAD of the session branch on the remote. Fetched and materialized using:

```bash
git fetch origin <session_branch>
git show origin/<session_branch>:<file>
```

# TREE-LEVEL MERGE

The `merge_trees()` function handles the full repository:

```
files = base.files ∪ local.files ∪ canonical.files
```

For each file, classify content as:
- **Text** - Valid UTF-8, can be merged
- **Binary** - Non-UTF-8, cannot be auto-merged  
- **Missing** - File doesn't exist in this tree

## Decision Matrix

| Base | Local | Canonical | Action |
|------|-------|-----------|--------|
| Text | Text | Text | 3-way text merge |
| Any | Changed | Unchanged | Take local |
| Any | Unchanged | Changed | Take canonical |
| Any | Same change | Same change | Take either |
| Binary | Changed | Changed | **Error** (conflict) |
| Missing | Present | Missing | Take local (new file) |
| Missing | Missing | Present | Take canonical (new file) |
| Present | Missing | Missing | Delete (both removed) |

Binary files that both sides modified differently cannot be auto-merged and require manual resolution.

# TEXT MERGE ALGORITHM

The `merge_file_yjs()` function implements a token-based 3-way merge using LCS.

## Fast Paths

Before running the full algorithm, check for trivial cases:

```rust
if local == base && canonical == base { return base; }
if local == base { return canonical; }  // Only remote changed
if canonical == base { return local; }  // Only local changed
if local == canonical { return local; } // Same change
```

## Tokenization

Text is split into alternating word and whitespace tokens:

```
"Hello  World" → ["Hello", "  ", "World"]
"a b\nc"       → ["a", " ", "b", "\n", "c"]
```

This preserves:
- Word boundaries for semantic merging
- Whitespace patterns including indentation
- Newlines as separate tokens

## LCS Computation

For each pair (base↔local and base↔canonical), compute the Longest Common Subsequence using dynamic programming:

```
Base:   ["The", " ", "quick", " ", "fox"]
Local:  ["The", " ", "slow", " ", "fox"]

LCS pairs: [(0,0), (1,1), (3,3), (4,4)]
           "The"   " "    " "   "fox"
```

The LCS identifies which tokens are **anchors** (unchanged) vs **modifications**.

## Merge Walk

Walk through base tokens, using LCS pairs as a map:

```rust
for base_idx in 0..base_tokens.len() {
    // 1. Output canonical insertions before this position
    // 2. Output local insertions before this position  
    // 3. Handle the base token based on what each side did
}
// 4. Output remaining insertions from both sides
```

### Handling Base Tokens

| Local kept? | Canonical kept? | Action |
|-------------|-----------------|--------|
| Yes | Yes | Output base token |
| Yes | No | Don't output (canonical deleted/replaced) |
| No | Yes | Don't output (local deleted/replaced) |
| No | No | Don't output (both modified) |

### Insertion Order

When both sides insert at the same position:
1. Canonical insertions come first
2. Local insertions come second

This ensures deterministic output regardless of merge order.

# EXAMPLES

## Example 1: Non-overlapping edits

```
Base:      "The quick brown fox"
Local:     "The slow brown fox"     (changed "quick" → "slow")
Canonical: "The quick brown dog"    (changed "fox" → "dog")
Result:    "The slow brown dog"     (both changes applied)
```

## Example 2: Same position, different changes

```
Base:      "Hello World"
Local:     "Hi World"               (changed "Hello" → "Hi")  
Canonical: "Hey World"              (changed "Hello" → "Hey")
Result:    "HeyHi World"            (both replacements kept)
```

This is the **additive merge** behavior - no data is lost.

## Example 3: Deletions

```
Base:      "A B C D"
Local:     "A C D"                  (deleted "B")
Canonical: "A B D"                  (deleted "C")
Result:    "A D"                    (both deletions applied)
```

## Example 4: Insertions at same point

```
Base:      "A B"
Local:     "A X B"                  (inserted "X" after "A")
Canonical: "A Y B"                  (inserted "Y" after "A")
Result:    "A Y X B"                (canonical first, then local)
```

# ALGORITHM PROPERTIES

## Guarantees

- **Deterministic** - Same inputs always produce same output
- **No conflicts** - Always produces a result for text files
- **No data loss** - All changes from both sides are preserved
- **Associative** - `merge(merge(a,b), c) = merge(a, merge(b,c))`

## Trade-offs

- **Additive semantics** - When both sides change the same text, both versions appear in output
- **No semantic understanding** - Merges at token level, not code structure
- **Binary conflicts** - Cannot auto-merge binary files with concurrent changes

## Complexity

- **Time**: O(n²) for LCS computation where n = token count
- **Space**: O(n²) for DP table

For typical source files (< 10,000 tokens), this is fast enough.

# SYNC FLOW

The complete sync operation:

```
1. Lock canonical repository
2. Fetch latest from origin
3. Materialize base_tree (from last_synced_commit)
4. Materialize local_tree (from worktree filesystem)
5. Materialize canonical_tree (from origin/branch)
6. Detect if changes exist on either side
7. merge_trees(base, local, canonical) → merged
8. Apply merged tree to canonical repo
9. Commit changes
10. Update metadata (new last_synced_commit)
11. Release lock
12. Push to origin
13. Refresh worktree from canonical
14. Log sync activity
```

# DEBUGGING

Enable merge debugging:

```bash
export STEADYSTATE_DEBUG_MERGE=1
steadystate sync
```

This logs:
- File-by-file merge decisions
- Tree sizes
- Which files have changes

# LIMITATIONS

## Binary Files

Binary files (images, PDFs, compiled assets) cannot be text-merged. If both local and canonical modify the same binary file:

```
Error: Binary file conflict in 'image.png'
Manual resolution required.
```

**Workaround**: Coordinate with collaborators, or one person reverts their change.

## Very Large Files

The O(n²) LCS algorithm may be slow for files with millions of tokens. For typical code and data files, this is not an issue.

## Semantic Conflicts

The merge is purely textual. It cannot detect:
- Duplicate function definitions
- Incompatible API changes
- Logical contradictions

These must be caught by testing or code review after merge.

# SEE ALSO

**steadystate-sync**(1), **steadystate-architecture**(8)

# REFERENCES

- Longest Common Subsequence: https://en.wikipedia.org/wiki/Longest_common_subsequence
- Three-way merge: https://en.wikipedia.org/wiki/Merge_(version_control)#Three-way_merge
