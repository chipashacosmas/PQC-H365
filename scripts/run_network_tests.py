#!/usr/bin/env python3
import subprocess
import sys
import time
from pathlib import Path


TESTS = [
    {
        "name": "basic_tcp",
        "server": "pqc_server",
        "client": "pqc_client",
        "port": "4644",
        "client_expect": ["SERVER_HELLO_FRAME_OK", "basic round-trip handshake time"],
        "server_expect": ["CLIENT_HELLO_FRAME_OK", "basic handshake time"],
    },
    {
        "name": "ml_kem_tcp",
        "server": "pqc_kem_server",
        "client": "pqc_kem_client",
        "port": "4645",
        "client_expect": ["received public key: 1184 bytes", "client shared secret SHA256 prefix"],
        "server_expect": ["received ciphertext: 1088 bytes", "server shared secret SHA256 prefix"],
    },
    {
        "name": "x25519_tcp",
        "server": "pqc_x25519_server",
        "client": "pqc_x25519_client",
        "port": "4646",
        "client_expect": ["received server public key: 32 bytes", "client X25519 shared secret SHA256 prefix"],
        "server_expect": ["received client public key: 32 bytes", "server X25519 shared secret SHA256 prefix"],
    },
    {
        "name": "hybrid_seq_tcp",
        "server": "pqc_hybrid_seq_server",
        "client": "pqc_hybrid_seq_client",
        "port": "4647",
        "client_expect": ["client session key SHA256 prefix", "result: PASS"],
        "server_expect": ["server session key SHA256 prefix", "result: PASS"],
    },
    {
        "name": "hybrid_par_tcp",
        "server": "pqc_hybrid_par_server",
        "client": "pqc_hybrid_par_client",
        "port": "4648",
        "client_expect": ["client session key SHA256 prefix", "result: PASS"],
        "server_expect": ["server session key SHA256 prefix", "result: PASS"],
    },
    {
        "name": "dsa_auth_tcp",
        "server": "pqc_dsa_auth_server",
        "client": "pqc_dsa_auth_client",
        "port": "4649",
        "client_expect": ["received signature: 3309 bytes", "result: PASS"],
        "server_expect": ["sent signature: 3309 bytes", "result: PASS"],
    },
    {
        "name": "hybrid_auth_tcp",
        "server": "pqc_hybrid_auth_server",
        "client": "pqc_hybrid_auth_client",
        "port": "4650",
        "client_expect": ["client authenticated session key SHA256 prefix", "result: PASS"],
        "server_expect": ["server authenticated session key SHA256 prefix", "result: PASS"],
    },
    {
        "name": "secure_transport_tcp",
        "server": "pqc_secure_server",
        "client": "pqc_secure_client",
        "port": "4651",
        "client_expect": ["transcript verification: PASS", "result: PASS"],
        "server_expect": ["decrypted plaintext: PQC secure payload after authenticated hybrid handshake", "result: PASS"],
    },
]


def output_has_all(output, expected):
    return all(item in output for item in expected)


def run_test(build_dir, test):
    server_path = build_dir / test["server"]
    client_path = build_dir / test["client"]

    server = subprocess.Popen(
        [str(server_path), test["port"]],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        time.sleep(0.15)
        if server.poll() is not None:
            server_output, _ = server.communicate(timeout=2)
            return False, "", server_output

        client = subprocess.run(
            [str(client_path), "127.0.0.1", test["port"]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
        server_output, _ = server.communicate(timeout=15)
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server.kill()

    client_ok = client.returncode == 0 and output_has_all(client.stdout, test["client_expect"])
    server_ok = server.returncode == 0 and output_has_all(server_output, test["server_expect"])
    return client_ok and server_ok, client.stdout, server_output


def main():
    root = Path.cwd()
    build_dir = root / "build"

    failures = 0
    for test in TESTS:
        ok, client_output, server_output = run_test(build_dir, test)
        print(f"{test['name']}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures += 1
            print("client output:")
            print(client_output)
            print("server output:")
            print(server_output)

    if failures:
        print(f"\nNetwork tests failed: {failures}", file=sys.stderr)
        return 1

    print("\nAll network correctness tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

