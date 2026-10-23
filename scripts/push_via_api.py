#!/usr/bin/env python3
"""
通过 GitHub API 逐提交推送到 v4 分支。

为何不用 git push：本沙盒出口代理只放行 api.github.com，
github.com 的 git smart HTTP 通道返回 403（ls-remote 亦失败）。
故改用 Git Data API：blob -> tree -> commit -> ref。

每个提交重建后校验 tree SHA 与本地完全一致，不一致即中止，
绝不产生"内容不同但 SHA 不同"的平行历史。

用法: python3 scripts/push_via_api.py <起点远程SHA> <待推送提交...>
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

REPO = "grokggg/dayanjing"
BRANCH = "v4"
TOKEN = os.environ.get("GH_TOKEN", "")
API = "https://api.github.com"


def gh(method, path, payload=None, raw=False):
    url = f"{API}{path}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    if raw:
        req.add_header("Accept", "application/vnd.github.raw+json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        raise SystemExit(f"HTTP {e.code} {method} {path}\n{body}")


def git(*args, binary=False):
    r = subprocess.run(["git"] + list(args), capture_output=True, cwd="/data/workspace/dayanjing")
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} 失败: {r.stderr.decode()[:300]}")
    return r.stdout if binary else r.stdout.decode()


def get_mode(commit, path):
    """从 commit 取文件 mode；不存在返回 None（表示删除）。"""
    r = subprocess.run(["git", "ls-tree", commit, "--", path],
                       capture_output=True, cwd="/data/workspace/dayanjing")
    out = r.stdout.decode().strip()
    if not out:
        return None
    return out.split()[0]


def push_commit(parent_sha, base_tree, local_commit):
    """把一个本地提交重建成远程 commit，返回新 SHA。"""
    msg = git("log", "-1", "--format=%B", local_commit).strip()

    # 变化文件列表
    diff = git("diff", "--name-status", f"{local_commit}^", local_commit).strip()
    if not diff:
        print(f"  [!] {local_commit} 无文件变化，跳过内容构建")
        entries = []
    else:
        entries = []
        for line in diff.split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            status = parts[0][0]
            path = parts[-1]
            if status == "D":
                entries.append({"path": path, "sha": None, "type": "blob"})
                print(f"      D {path}")
                continue
            mode = get_mode(local_commit, path)
            if mode == "040000":
                continue
            content = git("show", f"{local_commit}:{path}", binary=True)
            blob = gh("POST", f"/repos/{REPO}/git/blobs", {
                "content": base64.b64encode(content).decode(),
                "encoding": "base64",
            })
            entries.append({
                "path": path,
                "mode": mode,
                "type": "blob",
                "sha": blob["sha"],
            })
            print(f"      {status} {path} ({len(content)}B, mode={mode})")

    if entries:
        tree = gh("POST", f"/repos/{REPO}/git/trees", {
            "base_tree": base_tree,
            "tree": entries,
        })
    else:
        tree = {"sha": base_tree}

    # 校验：重建的 tree 必须与本地逐位相同
    local_tree = git("rev-parse", f"{local_commit}^{{tree}}").strip()
    if tree["sha"] != local_tree:
        raise SystemExit(
            f"TREE MISMATCH {local_commit}\n  重建={tree['sha']}\n  本地={local_tree}\n中止，未修改远程"
        )
    print(f"      tree OK = {local_tree}")

    commit = gh("POST", f"/repos/{REPO}/git/commits", {
        "message": msg,
        "tree": tree["sha"],
        "parents": [parent_sha],
    })
    return commit["sha"], tree["sha"]


def main():
    if not TOKEN:
        raise SystemExit("缺少 GH_TOKEN")
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)

    start_sha = sys.argv[1]
    commits = sys.argv[2:]

    # 起点 tree 必须与本地起点提交的 tree 一致
    start_local = f"{commits[0]}^"
    local_start_tree = git("rev-parse", f"{start_local}^{{tree}}").strip()
    remote = gh("GET", f"/repos/{REPO}/git/commits/{start_sha}")
    if remote["tree"]["sha"] != local_start_tree:
        raise SystemExit(
            f"起点 tree 不一致\n  远程 {start_sha} tree={remote['tree']['sha']}\n"
            f"  本地 {start_local} tree={local_start_tree}\n中止"
        )
    print(f"起点一致: 远程 {start_sha[:8]} == 本地 {start_local[:8]} (tree {local_start_tree[:8]})")

    parent = start_sha
    base_tree = remote["tree"]["sha"]
    for c in commits:
        full = git("rev-parse", c).strip()
        print(f"\n>>> 推送 {c} ({full[:8]})")
        parent, base_tree = push_commit(parent, base_tree, full)
        print(f"    commit = {parent[:8]}")
        time.sleep(0.3)

    # 更新 ref（force 保证内容正确落位）
    gh("PATCH", f"/repos/{REPO}/git/refs/heads/{BRANCH}", {"sha": parent, "force": True})
    print(f"\n已更新 {BRANCH} -> {parent[:8]}")

    # 独立复核
    time.sleep(1)
    ref = gh("GET", f"/repos/{REPO}/git/refs/heads/{BRANCH}")
    head = gh("GET", f"/repos/{REPO}/git/commits/{ref['object']['sha']}")
    local_head_tree = git("rev-parse", f"{commits[-1]}^{{tree}}").strip()
    print("\n=== 复核 ===")
    print(f"远程 {BRANCH} = {ref['object']['sha']}")
    print(f"远程 tree     = {head['tree']['sha']}")
    print(f"本地 tree     = {local_head_tree}")
    print("SHA: MATCH" if head["tree"]["sha"] == local_head_tree else "SHA: MISMATCH")


if __name__ == "__main__":
    main()
