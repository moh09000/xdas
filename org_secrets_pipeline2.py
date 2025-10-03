#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
org_secrets_pipeline.py

Single-file pipeline:
 - enumerate GitHub org repos (requires GITHUB_TOKEN env var for better rate limits)
 - optionally enumerate repos of org members (--expand-members)
 - clone each repo as --mirror to preserve history
 - scan git history blobs for secrets (built-in regexes)
 - optionally run TruffleHog and merge its hits
 - write unified final output: secrets_exposed.json

Usage:
  export GITHUB_TOKEN=ghp_xxx
  python3 org_secrets_pipeline.py --org makemytrip

Options:
  --outdir ./out_repos           output base dir (default: ./<org>_scan)
  --workers 4                    concurrent clone+scan workers
  --trufflehog-path trufflehog   path to trufflehog binary (optional)
  --only-deleted                 report only files present in history but not in HEAD
  --skip-archived                skip archived repos
  --no-forks                     skip forks
  --max-repos N                  limit number of repos to process (for testing)
  --max-hashes N                 limit number of unique objects scanned per repo (for testing)
  --expand-members               also include repos owned by org members
  --max-member-repos N           limit per-member repos when expanding (0 = no limit)
"""

import argparse
import os
import sys
import json
import time
import shutil
import subprocess
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests
import re
from datetime import datetime
from typing import List, Dict, Any

# -----------------------
# Config & patterns
# -----------------------
GITHUB_API = "https://api.github.com"
REGEX_PATTERNS = {
    "AWS Access Key ID": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key (likely)": re.compile(rb"(?i)aws(.{0,20})?(secret|secret_access_key|access_key|secretkey)[\"'`:= ]+([A-Za-z0-9/+=]{40,})"),
    "Google API key (AIza...)": re.compile(rb"AIza[0-9A-Za-z\-_]{35,}"),
    "Slack token (xox[baprs]-...)": re.compile(rb"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
    "Private RSA key start": re.compile(rb"-----BEGIN (RSA )?PRIVATE KEY-----"),
    "Generic API token-like": re.compile(rb"(?i)(api[_-]?key|token|access[_-]?token)[\"'`:= ]+([A-Za-z0-9\-_\.]{16,200})"),
    "Generic password in obvious file": re.compile(rb"(?i)(password|passwd|pwd)[\"'` :=]+[^\s\"']{6,100}"),
}
BINARY_NULL_THRESHOLD = 8
SNIPPET_CONTEXT = 80

# -----------------------
# Helpers
# -----------------------
def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)

def run_cmd(cmd, cwd=None, timeout=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, b"", str(e).encode()
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"

# -----------------------
# GitHub enumeration
# -----------------------
def github_list_org_repos(org: str, token: str = None, include_forks: bool = True, include_archived: bool = True, max_repos: int = None) -> List[Dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"{GITHUB_API}/orgs/{org}/repos?per_page=100&type=all"
    repos = []
    while url:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            eprint(f"[!] GitHub API error {r.status_code}: {r.text[:300]}")
            break
        page = r.json()
        for item in page:
            if not include_forks and item.get("fork"):
                continue
            if not include_archived and item.get("archived"):
                continue
            repos.append({
                "full_name": item.get("full_name"),
                "name": item.get("name"),
                "clone_url": item.get("clone_url"),
                "ssh_url": item.get("ssh_url"),
                "private": item.get("private", False),
                "archived": item.get("archived", False),
                "description": item.get("description"),
                "owner_login": item.get("owner", {}).get("login")
            })
            if max_repos and len(repos) >= max_repos:
                return repos
        link = r.headers.get("Link", "")
        next_url = None
        if 'rel="next"' in link:
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip().strip("<>")
        url = next_url
    return repos

def github_list_org_members(org: str, token: str) -> List[Dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"{GITHUB_API}/orgs/{org}/members?per_page=100"
    members = []
    while url:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            eprint(f"[!] GitHub API error {r.status_code} when listing members: {r.text[:300]}")
            break
        page = r.json()
        for m in page:
            # each member item contains 'login', 'id', etc.
            members.append(m)
        link = r.headers.get("Link", "")
        next_url = None
        if 'rel="next"' in link:
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip().strip("<>")
        url = next_url
    return members

def github_list_user_repos(user: str, token: str, include_forks: bool = True, include_archived: bool = True, max_repos: int = None) -> List[Dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"{GITHUB_API}/users/{user}/repos?per_page=100&type=owner"
    repos = []
    while url:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            eprint(f"[!] GitHub API error {r.status_code} when listing user {user} repos: {r.text[:300]}")
            break
        page = r.json()
        for item in page:
            if not include_forks and item.get("fork"):
                continue
            if not include_archived and item.get("archived"):
                continue
            repos.append({
                "full_name": item.get("full_name"),
                "name": item.get("name"),
                "clone_url": item.get("clone_url"),
                "ssh_url": item.get("ssh_url"),
                "private": item.get("private", False),
                "archived": item.get("archived", False),
                "description": item.get("description"),
                "owner_login": item.get("owner", {}).get("login")
            })
            if max_repos and len(repos) >= max_repos:
                return repos
        link = r.headers.get("Link", "")
        next_url = None
        if 'rel="next"' in link:
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip().strip("<>")
        url = next_url
    return repos

# -----------------------
# Cloning (mirror)
# -----------------------
def clone_repo_mirror(clone_url: str, dest_parent: str, full_name: str, retries: int = 2, timeout: int = 900) -> str:
    """
    Clone as --mirror into dest_parent/<safe_name>.git
    Returns path to mirror dir or empty string on failure.
    """
    safe_name = full_name.replace("/", "__")
    dest = os.path.join(dest_parent, f"{safe_name}.git")
    if os.path.isdir(dest):
        return dest
    cmd = ["git", "clone", "--mirror", clone_url, dest]
    tries = 0
    while tries <= retries:
        tries += 1
        code, out, err = run_cmd(cmd, timeout=timeout)
        if code == 0:
            return dest
        eprint(f"[!] clone attempt {tries} failed for {full_name}: {err.decode(errors='replace')[:300]}")
        time.sleep(2 * tries)
    return ""

# -----------------------
# Git history scanning core
# -----------------------
def list_rev_objects(repo_dir: str) -> List[tuple]:
    code, out, err = run_cmd(["git", "rev-list", "--objects", "--all"], cwd=repo_dir)
    if code != 0:
        raise RuntimeError("git rev-list failed: " + (err.decode(errors='replace')[:400]))
    lines = out.decode(errors='replace').splitlines()
    objs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            objs.append((parts[0].strip(), parts[1].strip()))
        else:
            objs.append((parts[0].strip(), ""))
    return objs

def cat_object(repo_dir: str, obj_hash: str) -> bytes:
    code, out, err = run_cmd(["git", "cat-file", "-p", obj_hash], cwd=repo_dir)
    if code != 0:
        return b""
    return out

def is_maybe_text(b: bytes) -> bool:
    sample = b[:1024]
    return sample.count(b'\x00') < BINARY_NULL_THRESHOLD

def bytes_snippet(b: bytes, start:int, end:int, max_len=400) -> str:
    try:
        s = b[start:end].decode('utf-8', errors='replace')
    except Exception:
        s = str(b[start:end])
    s = s.replace('\r\n', '\n').strip()
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s

def find_regex_matches(blob: bytes) -> List[Dict[str, Any]]:
    findings = []
    for name, rx in REGEX_PATTERNS.items():
        for m in rx.finditer(blob):
            s = max(m.start() - SNIPPET_CONTEXT, 0)
            e = min(m.end() + SNIPPET_CONTEXT, len(blob))
            findings.append({
                "pattern_name": name,
                "match": (m.group(0).decode('utf-8', errors='replace') if isinstance(m.group(0), (bytes, bytearray)) else str(m.group(0))),
                "context_snippet": bytes_snippet(blob, s, e),
                "start": m.start(),
                "end": m.end()
            })
    return findings

def list_head_paths(repo_dir: str) -> set:
    # Try listing HEAD files; works if repo mirror has refs
    code, out, err = run_cmd(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=repo_dir)
    if code == 0:
        return set([l.strip() for l in out.decode(errors='replace').splitlines() if l.strip()])
    # fallback: try find default ref
    code2, out2, err2 = run_cmd(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=repo_dir)
    if code2 == 0:
        ref = out2.decode(errors='replace').strip().split("/")[-1]
        tmp_branch = "tmp_scan_branch_for_listing"
        code3, _, _ = run_cmd(["git", "branch", "--no-track", tmp_branch, f"refs/remotes/origin/{ref}"], cwd=repo_dir)
        if code3 == 0:
            code4, out4, _ = run_cmd(["git", "ls-tree", "-r", "--name-only", tmp_branch], cwd=repo_dir)
            run_cmd(["git", "branch", "-D", tmp_branch], cwd=repo_dir)
            if code4 == 0:
                return set([l.strip() for l in out4.decode(errors='replace').splitlines() if l.strip()])
    return set()

# -----------------------
# TruffleHog integration
# -----------------------
def run_trufflehog_filesystem(repo_path: str, trufflehog_path: str = "trufflehog", timeout: int = 600) -> List[Dict[str, Any]]:
    cmd = [trufflehog_path, "filesystem", "--json", repo_path]
    code, out, err = run_cmd(cmd, timeout=timeout)
    if code == 127:
        eprint("[!] trufflehog not found at path:", trufflehog_path)
        return []
    if out is None or len(out) == 0:
        return []
    text = out.decode('utf-8', errors='replace').strip()
    results = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            results = parsed
        elif isinstance(parsed, dict) and "results" in parsed and isinstance(parsed["results"], list):
            results = parsed["results"]
        else:
            results = [parsed]
    except json.JSONDecodeError:
        # NDJSON fallback
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except Exception:
                continue
    return results

def normalize_truffle_item(item: Dict[str, Any]) -> Dict[str, Any]:
    norm = {}
    norm["path"] = item.get("path") or item.get("file_path") or item.get("file") or None
    norm["match"] = None
    if "stringsFound" in item and item["stringsFound"]:
        norm["match"] = item["stringsFound"][0]
    elif "strings" in item and item["strings"]:
        norm["match"] = item["strings"][0]
    else:
        norm["match"] = item.get("match") or item.get("secret")
    norm["rule"] = item.get("rule") or item.get("regex")
    norm["entropy"] = item.get("entropy") or item.get("entropyScore")
    norm["commit"] = item.get("commit") or item.get("commitHash")
    norm["raw"] = item
    return norm

# -----------------------
# Per-repo full scan orchestration
# -----------------------
def scan_single_repo(mirror_path: str, repo_meta: dict, only_deleted: bool = False, trufflehog_path: str = None, max_hashes: int = None) -> Dict[str, Any]:
    """
    mirror_path: path to the mirrored repo (bare .git directory)
    repo_meta: original repo metadata (full_name, clone_url, etc.)
    """
    result = {
        "repo": repo_meta.get("full_name"),
        "mirror_path": mirror_path,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "findings": []
    }
    try:
        objects = list_rev_objects(mirror_path)
    except Exception as e:
        result["error"] = f"rev-list-failed: {str(e)}"
        return result

    hash_to_paths = {}
    for h, p in objects:
        hash_to_paths.setdefault(h, []).append(p)
    unique_hashes = list(hash_to_paths.keys())
    if max_hashes:
        unique_hashes = unique_hashes[:max_hashes]

    head_paths = list_head_paths(mirror_path)
    deleted_paths = set()
    if only_deleted:
        history_paths = {p for _, p in objects if p}
        deleted_paths = {p for p in history_paths if p and p not in head_paths}

    findings = []
    # scan blobs concurrently
    def worker_scan(h):
        blob = cat_object(mirror_path, h)
        if not blob:
            return None
        if not is_maybe_text(blob):
            return None
        paths = hash_to_paths.get(h, [])
        if only_deleted:
            if not any((p in deleted_paths) for p in paths if p):
                return None
        matches = find_regex_matches(blob)
        if not matches:
            return None
        return {"object_hash": h, "paths": [p for p in paths if p], "matches": matches}

    # reasonable concurrency to avoid too many git-cat-file subshells at once
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(worker_scan, h): h for h in unique_hashes}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    findings.append(res)
            except Exception as e:
                eprint("[!] scanning error:", e)

    # run trufflehog if requested
    truffle_results = []
    if trufflehog_path:
        raw = run_trufflehog_filesystem(mirror_path, trufflehog_path=trufflehog_path)
        for item in raw:
            norm = normalize_truffle_item(item)
            truffle_results.append(norm)

    # merge findings (dedupe by path + match)
    merged = list(findings)
    seen = set()
    for f in merged:
        for m in f["matches"]:
            seen.add((tuple(f.get("paths", [])), m.get("match")))

    for t in truffle_results:
        key = (tuple([t.get("path")] if t.get("path") else []), t.get("match"))
        if key in seen:
            continue
        # convert truffle item into scanner-like entry
        merged.append({
            "object_hash": None,
            "paths": [t.get("path")] if t.get("path") else [],
            "matches": [{
                "pattern_name": f"trufflehog:{t.get('rule') or 'unknown'}",
                "match": t.get("match"),
                "context_snippet": t.get("match") or ""
            }],
            "trufflehog_meta": {
                "entropy": t.get("entropy"),
                "commit": t.get("commit"),
                "raw": t.get("raw")
            }
        })
        seen.add(key)

    result["findings"] = merged
    result["counts"] = {"objects_examined": len(unique_hashes), "findings_count": len(merged)}
    return result

# -----------------------
# Orchestrator: clone + scan per repo
# -----------------------
def process_repo_task(repo_meta: dict, base_outdir: str, only_deleted: bool, trufflehog_path: str, max_hashes: int) -> Dict[str, Any]:
    name = repo_meta.get("full_name")
    clone_url = repo_meta.get("clone_url")
    try:
        eprint(f"[*] Cloning {name} ...")
        mirror_path = clone_repo_mirror(clone_url, base_outdir, name)
        if not mirror_path:
            return {"repo": name, "status": "clone_failed"}
        eprint(f"[+] Cloned {name} -> {mirror_path}")
        # scan
        res = scan_single_repo(mirror_path, repo_meta, only_deleted=only_deleted, trufflehog_path=trufflehog_path, max_hashes=max_hashes)
        res["status"] = "scanned"
        # write per-repo json for later inspection
        out_json = os.path.join(base_outdir, f"{name.replace('/', '__')}_scan.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
        res["per_repo_json"] = out_json
        return res
    except Exception as e:
        return {"repo": name, "status": "error", "error": str(e)}

# -----------------------
# Main CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Org secrets pipeline: enumerate -> mirror clone -> scan history -> trufflehog -> aggregate.")
    p.add_argument("--org", required=True, help="GitHub organization name")
    p.add_argument("--outdir", default=None, help="Base output dir (default: ./<org>_scan)")
    p.add_argument("--workers", type=int, default=4, help="Concurrent clone+scan workers")
    p.add_argument("--trufflehog-path", default=None, help="Path to trufflehog (optional). Set if installed.")
    p.add_argument("--only-deleted", action="store_true", help="Report only files that were deleted from HEAD but still in history")
    p.add_argument("--skip-archived", action="store_true", help="Skip archived repos")
    p.add_argument("--no-forks", action="store_true", help="Skip forks")
    p.add_argument("--max-repos", type=int, default=0, help="Limit number of repos (0 = all)")
    p.add_argument("--max-hashes", type=int, default=0, help="Limit number of unique objects scanned per repo (0 = all) - for testing")
    p.add_argument("--expand-members", action="store_true", help="Also include public repos owned by org members")
    p.add_argument("--max-member-repos", type=int, default=0, help="Limit per-member repos when expanding (0 = no limit)")
    return p.parse_args()

def main():
    args = parse_args()
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        eprint("[!] Please set GITHUB_TOKEN environment variable (export GITHUB_TOKEN=...)")
        sys.exit(1)
    org = args.org
    base_outdir = args.outdir or f"./{org}_scan"
    os.makedirs(base_outdir, exist_ok=True)

    eprint(f"[*] Enumerating repos for org: {org}")
    repos = github_list_org_repos(org, token=token, include_forks=not args.no_forks, include_archived=not args.skip_archived, max_repos=(args.max_repos or None))
    if repos is None:
        eprint("[!] No repos found or GitHub API error.")
        sys.exit(1)
    eprint(f"[*] Org repos discovered: {len(repos)}")

    # expand to members if requested
    if args.expand_members:
        eprint("[*] Expanding to org members' public repos (this may be large)...")
        members = github_list_org_members(org, token)
        eprint(f"[*] Members discovered: {len(members)}")
        member_total = 0
        for m in members:
            login = m.get("login")
            if not login:
                continue
            try:
                user_repos = github_list_user_repos(login, token, include_forks=not args.no_forks, include_archived=not args.skip_archived, max_repos=(args.max_member_repos or None))
                eprint(f"  [+] {login}: {len(user_repos)} repos")
                repos.extend(user_repos)
                member_total += len(user_repos)
            except Exception as ex:
                eprint(f"  [!] Failed to list repos for {login}: {ex}")
        eprint(f"[*] Total member repos added: {member_total}")

    # dedupe repos by full_name (keep first encountered)
    deduped = {}
    for r in repos:
        fn = r.get("full_name") or r.get("name")
        if not fn:
            continue
        if fn in deduped:
            continue
        deduped[fn] = r
    all_repos = list(deduped.values())

    # apply global max_repos limit if provided
    if args.max_repos and args.max_repos > 0:
        all_repos = all_repos[:args.max_repos]

    eprint(f"[*] Total unique repos to process: {len(all_repos)}")

    tasks = []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(process_repo_task, r, base_outdir, args.only_deleted, args.trufflehog_path, (args.max_hashes or None)): r for r in all_repos}
        for fut in as_completed(futures):
            meta = futures[fut]
            try:
                res = fut.result()
                results.append(res)
                eprint(f"[+] Done: {meta.get('full_name')} -> status: {res.get('status')}")
            except Exception as e:
                eprint("[!] Task exception:", e)

    # aggregate final JSON
    final = {
        "organization": org,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "total_repos": len(all_repos),
        "results": results
    }
    out_file = os.path.join(base_outdir, "secrets_exposed.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)
    print("[*] DONE. Final aggregated results written to:", out_file)
    print("[*] Per-repo JSON files are in:", base_outdir)

if __name__ == "__main__":
    main()
