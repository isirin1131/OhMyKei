#!/usr/bin/env python3
"""Offline Wycheproof regression; only the bridge calls production C APIs."""
import collections
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def token(value):
    return value or "-"


def cases(data):
    for group in data["testGroups"]:
        for case in group["tests"]:
            yield group, case


def prepare(name, data):
    jobs = []
    skipped = collections.Counter()
    for group, case in cases(data):
        result = case["result"]
        assert result in ("valid", "invalid", "acceptable")
        label = f"{name} tcId={case['tcId']} ({','.join(case['flags'])})"
        expected = {"VALID" if result == "valid" else "INVALID"}
        if name == "hmac":
            if group["tagSize"] != 256:
                skipped["truncated tag (API computes full 32-byte MAC)"] += 1
                continue
            args = ["hmac", case["key"], case["msg"], case["tag"]]
        elif name == "hkdf":
            args = ["hkdf", case["salt"], case["ikm"], case["info"], str(case["size"])]
            expected = {"OK " + case["okm"]} if result == "valid" else {"ERR"}
            assert result == "valid" or (result == "invalid" and case["size"] > 8160)
        elif name == "ecdsa":
            assert group["sha"] == "SHA-256"
            assert group["publicKey"]["curve"] == "secp256r1"
            if len(bytes.fromhex(case["sig"])) != 64:
                skipped["signature length outside fixed 64-byte API"] += 1
                continue
            pub = group["publicKey"]["uncompressed"]
            assert len(bytes.fromhex(pub)) == 65
            digest = hashlib.sha256(bytes.fromhex(case["msg"])).hexdigest()
            args = ["ecdsa", pub, digest, case["sig"]]
        elif name == "ed25519":
            assert group["publicKey"]["curve"] == "edwards25519"
            if len(bytes.fromhex(case["sig"])) != 64:
                skipped["signature length outside fixed 64-byte API"] += 1
                continue
            args = ["ed25519", group["publicKey"]["pk"], case["msg"], case["sig"]]
            if result == "acceptable":
                flags = set(case["flags"])
                assert flags in ({"SmallOrderPublicKey"}, {"MixedOrderPublicKey"})
                # Our verifier rejects small-order public keys. Mixed-order
                # keys follow the uncofactored equation permitted by RFC 8032.
                expected = {"INVALID"} if "SmallOrderPublicKey" in flags else {"VALID", "INVALID"}
        elif name == "ecdh":
            assert group["curve"] == "secp256r1"
            if len(bytes.fromhex(case["public"])) != 65:
                skipped["point encoding outside fixed 65-byte API"] += 1
                continue
            # Wycheproof encodes the scalar as a variable-length integer,
            # including an optional sign-padding zero. Preserve its value.
            scalar = int(case["private"], 16)
            assert 0 <= scalar < (1 << 256)
            args = ["ecdh", scalar.to_bytes(32, "big").hex(), case["public"]]
            assert result != "acceptable"
            expected = {"OK " + case["shared"]} if result == "valid" else {"ERR"}
        else:
            raise ValueError(name)
        jobs.append((" ".join(map(token, args)), expected, label, result))
    assert len(jobs) + sum(skipped.values()) == data["numberOfTests"]
    return jobs, skipped


def main():
    bridge, vector_dir = sys.argv[1:]
    vectors = Path(vector_dir)
    manifest = json.loads((vectors / "manifest.json").read_text())
    for filename, digest in manifest["files"].items():
        if hashlib.sha256((vectors / filename).read_bytes()).hexdigest() != digest:
            raise ValueError(f"vector checksum mismatch: {filename}")
    files = {
        "hmac": "hmac_sha256_test.json",
        "hkdf": "hkdf_sha256_test.json",
        "ecdsa": "ecdsa_secp256r1_sha256_p1363_test.json",
        "ed25519": "ed25519_test.json",
        "ecdh": "ecdh_secp256r1_ecpoint_test.json",
    }
    failures = total = omitted = 0
    for name, filename in files.items():
        jobs, skipped = prepare(name, json.loads((vectors / filename).read_text()))
        result = subprocess.run([bridge], input="\n".join(job[0] for job in jobs) + "\n",
                                stdout=subprocess.PIPE, text=True, timeout=300)
        if result.returncode:
            print(f"FAIL: {name} bridge exited with status {result.returncode}")
            return 1
        replies = result.stdout.splitlines()
        if len(replies) != len(jobs):
            print(f"FAIL: {name} bridge response count mismatch")
            return 1
        accepted_policy = rejected_policy = 0
        for reply, (_, expected, label, category) in zip(replies, jobs):
            if reply not in expected:
                print(f"FAIL: {label}: unexpected result")
                failures += 1
            if category == "acceptable":
                accepted_policy += reply == "VALID"
                rejected_policy += reply == "INVALID"
        total += len(jobs)
        omitted += sum(skipped.values())
        print(f"{name}: executed={len(jobs)}, not_applicable={sum(skipped.values())}")
        for reason, count in skipped.items():
            print(f"  not_applicable: {count}: {reason}")
        if accepted_policy + rejected_policy:
            print(f"  acceptable: accepted={accepted_policy}, rejected={rejected_policy}")
    print(f"wycheproof: executed={total}, not_applicable={omitted}, failures={failures}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
