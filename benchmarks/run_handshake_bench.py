#!/usr/bin/env python3
import argparse
import csv
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


MODES = {
    "x25519": {
        "server": "pqc_x25519_server",
        "client": "pqc_x25519_client",
        "port": 4546,
        "metric": "network X25519 handshake time",
    },
    "ml_kem": {
        "server": "pqc_kem_server",
        "client": "pqc_kem_client",
        "port": 4545,
        "metric": "network ML-KEM handshake time",
    },
    "hybrid_seq": {
        "server": "pqc_hybrid_seq_server",
        "client": "pqc_hybrid_seq_client",
        "port": 4547,
        "metric": "sequential hybrid handshake time",
    },
    "hybrid_par": {
        "server": "pqc_hybrid_par_server",
        "client": "pqc_hybrid_par_client",
        "port": 4548,
        "metric": "parallel hybrid handshake time",
    },
    "hybrid_auth": {
        "server": "pqc_hybrid_auth_server",
        "client": "pqc_hybrid_auth_client",
        "port": 4550,
        "metric": "authenticated hybrid handshake time",
    },
    "secure_transport": {
        "server": "pqc_secure_server",
        "client": "pqc_secure_client",
        "port": 4551,
        "metric": "secure payload total time",
    },
}


TIME_RE = re.compile(r"^(?P<label>.+): (?P<value>[0-9]+(?:\.[0-9]+)?) ms$")
KEY_RE = re.compile(r"session key SHA256 prefix: (?P<key>[0-9a-f]+)|shared secret SHA256 prefix: (?P<secret>[0-9a-f]+)")


def parse_times(output):
    values = {}
    for line in output.splitlines():
        match = TIME_RE.search(line.strip())
        if match:
            values[match.group("label")] = float(match.group("value"))
    return values


def parse_fingerprint(output):
    for line in output.splitlines():
        match = KEY_RE.search(line)
        if match:
            return match.group("key") or match.group("secret")
    return ""


def run_once(build_dir, mode_name, run_index):
    mode = MODES[mode_name]
    server_path = build_dir / mode["server"]
    client_path = build_dir / mode["client"]
    port = str(mode["port"])

    server = subprocess.Popen(
        [str(server_path), port],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    server_output = ""
    try:
        time.sleep(0.15)
        if server.poll() is not None:
            server_output, _ = server.communicate(timeout=2)
            raise RuntimeError("server exited before client connected\n" + server_output)

        client = subprocess.run(
            [str(client_path), "127.0.0.1", port],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        remaining, _ = server.communicate(timeout=10)
        server_output += remaining
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server.kill()

    client_output = client.stdout
    if client.returncode != 0 or server.returncode != 0:
        raise RuntimeError(
            f"{mode_name} run {run_index} failed\n"
            f"client output:\n{client_output}\n"
            f"server output:\n{server_output}\n"
        )

    client_times = parse_times(client_output)
    server_times = parse_times(server_output)
    client_metric = client_times.get(mode["metric"])
    server_metric = server_times.get(mode["metric"])
    if client_metric is None or server_metric is None:
        raise RuntimeError(
            f"{mode_name} run {run_index} missing metric '{mode['metric']}'\n"
            f"client output:\n{client_output}\n"
            f"server output:\n{server_output}\n"
        )

    client_fp = parse_fingerprint(client_output)
    server_fp = parse_fingerprint(server_output)
    fingerprints_match = bool(client_fp and server_fp and client_fp == server_fp)

    return {
        "mode": mode_name,
        "run": run_index,
        "client_ms": client_metric,
        "server_ms": server_metric,
        "client_fingerprint": client_fp,
        "server_fingerprint": server_fp,
        "fingerprints_match": fingerprints_match,
    }


def summarize(rows):
    print("\nMode          Runs  Client avg/min/max ms        Server avg/min/max ms")
    print("------------  ----  -------------------------   -------------------------")
    for mode_name in MODES:
        mode_rows = [r for r in rows if r["mode"] == mode_name]
        if not mode_rows:
            continue
        client = [r["client_ms"] for r in mode_rows]
        server = [r["server_ms"] for r in mode_rows]
        print(
            f"{mode_name:<12}  {len(mode_rows):>4}  "
            f"{statistics.mean(client):>7.3f}/{min(client):>7.3f}/{max(client):>7.3f}   "
            f"{statistics.mean(server):>7.3f}/{min(server):>7.3f}/{max(server):>7.3f}"
        )


def main():
    parser = argparse.ArgumentParser(description="Run repeated PQC handshake benchmarks.")
    parser.add_argument("--build-dir", default="build", help="Directory containing compiled binaries.")
    parser.add_argument("--runs", type=int, default=10, help="Runs per mode.")
    parser.add_argument("--out", default="benchmarks/handshake_results.csv", help="CSV output path.")
    args = parser.parse_args()

    root = Path.cwd()
    build_dir = (root / args.build_dir).resolve()
    out_path = (root / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for mode_name in MODES:
        for run_index in range(1, args.runs + 1):
            row = run_once(build_dir, mode_name, run_index)
            rows.append(row)
            print(
                f"{mode_name} run {run_index}/{args.runs}: "
                f"client={row['client_ms']:.3f} ms "
                f"server={row['server_ms']:.3f} ms "
                f"match={row['fingerprints_match']}"
            )

    with out_path.open("w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summarize(rows)
    print(f"\nWrote CSV: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        sys.exit(1)
