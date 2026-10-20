#!/usr/bin/env python3
"""
14_p2p 部署器 —— 由拓扑定义生成可直接上机运行的节点目录。

产出结构:
    deploy/
      <alias>/
        node.conf     节点配置（含全部 peer 公钥与邻接关系）
        keys/<alias>.key   跳静态私钥（0600，绝不随包分发）
        start.sh      启动脚本
        stop.sh       停止脚本
      topology.json   实际使用的拓扑（含各节点 ID 与端口）
      run_all.sh      本地一键起全部节点（回环自检用）

用法:
    python3 deploy.py --topology topo.json --out deploy [--binary static/p2p_node]
    python3 deploy.py --topology topo.json --out deploy --run

设计原则:
  - 私钥只在目标机本地生成/保存，部署器不收集、不外传
  - 公钥通过 node 自身 --once 运行取回，再由部署器回填到各节点配置
  - 拓扑里的 host 一律用 IP 字面量，避免运行时依赖 DNS/NSS
"""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))   # .../dayanjing
DEFAULT_BINARY = os.path.join(ROOT, "14_p2p", "static", "p2p_node")


def pick_free_port(host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def gen_id():
    return secrets.token_hex(16)


def load_topology(path):
    with open(path) as f:
        t = json.load(f)
    if "nodes" not in t or not t["nodes"]:
        raise SystemExit("topology: 缺少 nodes")
    return t


def write_conf(path, alias, nid, role, host, port, statedir, keyfile,
               peers, neighbors, mgmt_port, probe_ms, seed, links=None):
    lines = [
        f"alias={alias}",
        f"id={nid}",
        f"role={role}",
        f"listen_host={host}",
        f"listen_port={port}",
        f"keyfile={keyfile}",
        f"statedir={statedir}",
        f"mgmt_port={mgmt_port}",
        f"probe_interval_ms={probe_ms}",
        f"seed={seed}",
    ]
    for pid, phost, pport, ppub in peers:
        if ppub:
            lines.append(f"peer={pid} {phost} {pport} {ppub}")
        else:
            lines.append(f"peer={pid} {phost} {pport}")
    for pid, phost, pport, ppub in neighbors:
        if ppub:
            lines.append(f"neighbor={pid} {phost} {pport} {ppub}")
        else:
            lines.append(f"neighbor={pid} {phost} {pport}")
    for la, lb in (links or []):
        lines.append(f"link={la} {lb}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def run_once(binary, conf):
    """跑一次 node --once：生成密钥并把公钥打印到 stderr"""
    r = subprocess.run([binary, "--config", conf, "--once"],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stderr or "").splitlines():
        if " pk=" in line:
            return line.split(" pk=")[1].strip().split()[0][:64]
    raise SystemExit(f"取公钥失败: {conf}\n{r.stderr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topology", required=True)
    ap.add_argument("--out", default="deploy")
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--run", action="store_true", help="生成后本地启动并自检")
    ap.add_argument("--echo-port", type=int, default=0,
                    help="最终目标 echo 服务端口（0=自动）")
    a = ap.parse_args()

    topo = load_topology(a.topology)
    if not os.path.exists(a.binary):
        raise SystemExit(f"二进制不存在: {a.binary}（先 make -C 14_p2p static）")

    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)

    # 1) 分配 ID 与端口
    nodes = {}
    for n in topo["nodes"]:
        alias = n["alias"]
        nodes[alias] = {
            "alias": alias,
            "role": n.get("role", "edge"),
            "id": gen_id(),
            "port": n.get("listen_port") or pick_free_port(a.host),
            "mgmt_port": pick_free_port(a.host),
            "neighbors": list(n.get("neighbors", [])),
            "pub": None,
        }

    peer_base = 40000
    # 全图邻接声明（去重后的无向边），每个节点都要写一份
    links = []
    seen = set()
    for al, nd in nodes.items():
        for nb in nd["neighbors"]:
            if nb not in nodes:
                continue
            key = tuple(sorted([al, nb]))
            if key in seen:
                continue
            seen.add(key)
            links.append((nodes[key[0]]["id"], nodes[key[1]]["id"]))
    # 2) 先写无公钥配置，跑 --once 生成密钥并取回公钥
    for alias, nd in nodes.items():
        d = os.path.join(out, alias)
        os.makedirs(os.path.join(d, "keys"), exist_ok=True)
        os.makedirs(os.path.join(d, "state"), exist_ok=True)
        peers = [(nodes[x]["id"], a.host, nodes[x]["port"], None)
                 for x in nodes if x != alias]
        nbrs = [(nodes[x]["id"], a.host, nodes[x]["port"], None)
                for x in nd["neighbors"] if x in nodes]
        conf = os.path.join(d, "node.conf")
        write_conf(conf, alias, nd["id"], nd["role"], a.host, nd["port"],
                   os.path.join(d, "state"), os.path.join(d, "keys", alias + ".key"),
                   peers, nbrs, nd["mgmt_port"],
                   topo.get("probe_interval_ms", 30000),
                   (peer_base + nd["port"]) & 0x7fffffff, links)
        nd["pub"] = run_once(a.binary, conf)
        print(f"[deploy] {alias}: id={nd['id']} port={nd['port']} pk={nd['pub'][:16]}...")

    # 3) 公钥回填，重写配置（此时每节点都持有全网公钥）
    for alias, nd in nodes.items():
        d = os.path.join(out, alias)
        peers = [(nodes[x]["id"], a.host, nodes[x]["port"], nodes[x]["pub"])
                 for x in nodes if x != alias]
        nbrs = [(nodes[x]["id"], a.host, nodes[x]["port"], nodes[x]["pub"])
                for x in nd["neighbors"] if x in nodes]
        write_conf(os.path.join(d, "node.conf"), alias, nd["id"], nd["role"],
                   a.host, nd["port"], os.path.join(d, "state"),
                   os.path.join(d, "keys", alias + ".key"), peers, nbrs,
                   nd["mgmt_port"], topo.get("probe_interval_ms", 30000),
                   (peer_base + nd["port"]) & 0x7fffffff, links)

    # 4) 启动/停止脚本
    bin_abs = os.path.abspath(a.binary)
    for alias, nd in nodes.items():
        d = os.path.join(out, alias)
        with open(os.path.join(d, "start.sh"), "w") as f:
            f.write(f"""#!/bin/sh
# {alias} —— 由 deploy.py 生成，可直接在目标机执行
cd "$(dirname "$0")" || exit 1
exec "{bin_abs}" --config node.conf
""")
        with open(os.path.join(d, "stop.sh"), "w") as f:
            f.write(f"""#!/bin/sh
pkill -f "p2p_node --config.*{alias}" 2>/dev/null
echo "stopped {alias}"
""")
        os.chmod(os.path.join(d, "start.sh"), 0o755)
        os.chmod(os.path.join(d, "stop.sh"), 0o755)

    with open(os.path.join(out, "run_all.sh"), "w") as f:
        f.write("#!/bin/sh\n# 本地一键起全部节点（回环自检）\ncd \"$(dirname \"$0\")\" || exit 1\n")
        for alias in nodes:
            f.write(f"(cd {alias} && ./start.sh) &\n")
        f.write("wait\n")
    os.chmod(os.path.join(out, "run_all.sh"), 0o755)

    meta = {
        "host": a.host,
        "binary": bin_abs,
        "probe_interval_ms": topo.get("probe_interval_ms", 30000),
        "nodes": {k: {"id": v["id"], "port": v["port"], "mgmt_port": v["mgmt_port"],
                      "role": v["role"], "pub": v["pub"],
                      "neighbors": v["neighbors"]}
                  for k, v in nodes.items()},
    }
    with open(os.path.join(out, "topology.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[deploy] 产出目录: {out}  节点数: {len(nodes)}")

    if a.run:
        run_local(out, meta, bin_abs, a.host, a.echo_port)


def run_local(out, meta, binary, host, echo_port):
    """真实启动全部节点 + echo 目标，做端到端贯通自检"""
    import signal
    procs = []
    echo_proc = None

    try:
        # echo 目标
        import threading
        esrv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        esrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        esrv.bind((host, echo_port or 0))
        esrv.listen(8)
        eport = esrv.getsockname()[1]
        print(f"[run] echo 目标监听 {host}:{eport}")

        def echo_loop():
            while True:
                try:
                    c, _ = esrv.accept()
                except OSError:
                    return
                threading.Thread(target=lambda cc=c: (
                    cc.sendall(cc.recv(65536)), cc.close()), daemon=True).start()

        threading.Thread(target=echo_loop, daemon=True).start()

        # 启动节点（除 endpoint 外全部 daemon）
        for alias, nd in meta["nodes"].items():
            d = os.path.join(out, alias)
            log = open(os.path.join(d, "run.log"), "w")
            p = subprocess.Popen([binary, "--config", "node.conf"],
                                 cwd=d, stdout=log, stderr=subprocess.STDOUT)
            procs.append((alias, p))
            print(f"[run] {alias} 启动 pid={p.pid} port={nd['port']}")
        time.sleep(2.0)

        alive = sum(1 for _, p in procs if p.poll() is None)
        print(f"[run] 存活节点 {alive}/{len(procs)}")
        if alive != len(procs):
            raise SystemExit("[run] 有节点退出，自检失败")

        # 状态文件检查
        ok_state = 0
        for alias in meta["nodes"]:
            sp = os.path.join(out, alias, "state", alias + ".json")
            if os.path.exists(sp):
                with open(sp) as f:
                    st = json.load(f)
                if st.get("alias") == alias:
                    ok_state += 1
        print(f"[run] 状态文件就绪 {ok_state}/{len(meta['nodes'])}")

        # 端到端：endpoint 建洋葱电路到 core，末端连 echo
        ep = next((a for a, n in meta["nodes"].items()
                   if n["role"] == "endpoint"), None)
        core = next((a for a, n in meta["nodes"].items()
                     if n["role"] == "core"), None)
        if ep and core:
            payload = b"E2E-" + secrets.token_hex(16).encode()
            cmd = [binary, "--config", "node.conf", "--connect",
                   meta["nodes"][core]["id"], host, str(eport)]
            r = subprocess.run(cmd, cwd=os.path.join(out, ep),
                               input=payload, capture_output=True, timeout=60)
            got = r.stdout
            head = (r.stderr or b"").decode(errors="replace")
            hops = [l for l in head.splitlines() if l.startswith("[node] hop")]
            print(f"[run] 电路跳数 {len(hops)}: {hops}")
            if got == payload:
                print(f"[run] 端到端贯通 PASS  ({len(payload)} 字节回显一致)")
            else:
                print(f"[run] 端到端 FAIL: 期望 {payload!r} 实收 {got!r}")
                print(head[-800:])
        else:
            print("[run] 拓扑缺 endpoint 或 core，跳过端到端")

    finally:
        for _, p in procs:
            try:
                p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        for _, p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        print("[run] 全部节点已停止")


if __name__ == "__main__":
    main()
