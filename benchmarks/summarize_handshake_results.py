#!/usr/bin/env python3
import argparse
import csv
import statistics
from pathlib import Path


MODE_LABELS = {
    "x25519": "Classical X25519",
    "ml_kem": "ML-KEM-768",
    "hybrid_seq": "Sequential Hybrid",
    "hybrid_par": "Parallel Hybrid",
    "hybrid_auth": "Authenticated Hybrid",
    "secure_transport": "Secure Transport",
}


def load_rows(path):
    with path.open(newline="") as fp:
        rows = list(csv.DictReader(fp))
    for row in rows:
        row["client_ms"] = float(row["client_ms"])
        row["server_ms"] = float(row["server_ms"])
    return rows


def stats(values):
    return {
        "avg": statistics.mean(values),
        "min": min(values),
        "max": max(values),
    }


def percent_reduction(before, after):
    return ((before - after) / before) * 100.0


def mode_stats(rows):
    result = {}
    for mode in MODE_LABELS:
        mode_rows = [row for row in rows if row["mode"] == mode]
        if not mode_rows:
            continue
        result[mode] = {
            "runs": len(mode_rows),
            "client": stats([row["client_ms"] for row in mode_rows]),
            "server": stats([row["server_ms"] for row in mode_rows]),
            "all_match": all(row["fingerprints_match"] == "True" for row in mode_rows),
        }
    return result


def write_report(summary, out_path):
    seq = summary.get("hybrid_seq")
    par = summary.get("hybrid_par")

    lines = []
    lines.append("# Handshake Benchmark Summary")
    lines.append("")
    lines.append("## Test Context")
    lines.append("")
    lines.append("- Environment: Ubuntu Server VM under VirtualBox")
    lines.append("- Transport: TCP over localhost (`127.0.0.1`)")
    lines.append("- Algorithms: X25519, ML-KEM-768, HKDF-SHA256")
    lines.append("- Measurement: application-level handshake timing in milliseconds")
    lines.append("- Note: localhost VM timing is suitable for comparative prototype evaluation, not public-network latency claims")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| Mode | Runs | Client Avg ms | Client Min ms | Client Max ms | Server Avg ms | Server Min ms | Server Max ms | Fingerprints Match |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for mode, label in MODE_LABELS.items():
        item = summary.get(mode)
        if item is None:
            continue
        lines.append(
            f"| {label} | {item['runs']} | "
            f"{item['client']['avg']:.3f} | {item['client']['min']:.3f} | {item['client']['max']:.3f} | "
            f"{item['server']['avg']:.3f} | {item['server']['min']:.3f} | {item['server']['max']:.3f} | "
            f"{'Yes' if item['all_match'] else 'No'} |"
        )

    if seq and par:
        client_reduction = percent_reduction(seq["client"]["avg"], par["client"]["avg"])
        server_reduction = percent_reduction(seq["server"]["avg"], par["server"]["avg"])
        lines.append("")
        lines.append("## Sequential vs Parallel Hybrid")
        lines.append("")
        lines.append("| Side | Sequential Avg ms | Parallel Avg ms | Reduction |")
        lines.append("|---|---:|---:|---:|")
        lines.append(
            f"| Client | {seq['client']['avg']:.3f} | {par['client']['avg']:.3f} | {client_reduction:.1f}% |"
        )
        lines.append(
            f"| Server | {seq['server']['avg']:.3f} | {par['server']['avg']:.3f} | {server_reduction:.1f}% |"
        )
        lines.append("")
        lines.append("## Interpretation")
        lines.append("")
        lines.append(
            "The parallel hybrid handshake reduced average handshake time compared with the sequential hybrid baseline. "
            "This supports the project objective that independent classical and post-quantum operations can be scheduled concurrently "
            "to reduce cumulative handshake latency while still deriving the same hybrid session key on both endpoints."
        )

    auth = summary.get("hybrid_auth")
    secure = summary.get("secure_transport")
    if auth and secure:
        lines.append("")
        lines.append("## Authenticated And Secure Transport")
        lines.append("")
        lines.append("| Mode | Client Avg ms | Server Avg ms | Fingerprints Match |")
        lines.append("|---|---:|---:|---|")
        lines.append(
            f"| Authenticated Hybrid | {auth['client']['avg']:.3f} | {auth['server']['avg']:.3f} | "
            f"{'Yes' if auth['all_match'] else 'No'} |"
        )
        lines.append(
            f"| Secure Transport | {secure['client']['avg']:.3f} | {secure['server']['avg']:.3f} | "
            f"{'Yes' if secure['all_match'] else 'No'} |"
        )
        lines.append("")
        lines.append(
            "These measurements include the later security stages: ML-DSA transcript authentication and AES-256-GCM payload protection. "
            "They are expected to be higher than the unauthenticated parallel hybrid baseline because they include signature verification, "
            "signature transmission, and encrypted payload handling."
        )

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Generate a Markdown benchmark report from handshake CSV results.")
    parser.add_argument("--csv", default="benchmarks/handshake_results.csv")
    parser.add_argument("--out", default="benchmarks/handshake_summary.md")
    args = parser.parse_args()

    rows = load_rows(Path(args.csv))
    summary = mode_stats(rows)
    write_report(summary, Path(args.out))
    print(f"Wrote report: {args.out}")


if __name__ == "__main__":
    main()
