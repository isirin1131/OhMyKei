#!/usr/bin/env python3
"""Offline NIST CAVP AES-256 ECB/CBC and byte-oriented SHA-256 vectors."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def records(path):
    section = ""
    record = {}
    for line in path.read_text().splitlines() + [""]:
        line = line.strip()
        if not line:
            if record:
                yield section, record
                record = {}
        elif line.startswith('#'):
            continue
        elif line.startswith('['):
            assert not record
            section = line[1:-1]
        else:
            key, value = line.split('=', 1)
            assert key.strip() not in record
            record[key.strip()] = value.strip()


def prepare(path):
    jobs = []
    seed = None
    for section, case in records(path):
        if path.name.startswith('SHA'):
            assert section == 'L = 32'
            if 'Seed' in case:
                seed = case['Seed'].lower()
                continue
            if 'Monte' in path.name:
                assert seed is not None
                args = ['sha256_monte', seed]
                seed = case['MD'].lower()
            else:
                bits = int(case['Len'])
                assert bits % 8 == 0
                msg = '' if bits == 0 else case['Msg']
                assert len(bytes.fromhex(msg)) == bits // 8
                args = ['sha256', msg or '-']
            expected = case['MD'].lower()
        else:
            assert section in ('ENCRYPT', 'DECRYPT')
            mode = path.name[:3].lower()
            encrypt = section == 'ENCRYPT'
            source, target = ('PLAINTEXT', 'CIPHERTEXT') if encrypt else ('CIPHERTEXT', 'PLAINTEXT')
            args = [mode + ('_enc' if encrypt else '_dec'), case['KEY'],
                    case.get('IV', '00' * 16), case[source]]
            expected = case[target].lower()
        label = f"{path.name} {section} case={case.get('COUNT', len(jobs))}"
        jobs.append((' '.join(args), 'OK ' + expected, label))
    assert jobs
    return jobs


def main():
    bridge, directory = sys.argv[1:]
    root = Path(directory)
    manifest = json.loads((root / 'manifest.json').read_text())
    total = failures = 0
    for filename, metadata in manifest['files'].items():
        path = root / filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != metadata['sha256']:
            raise ValueError(f'vector checksum mismatch: {filename}')
        jobs = prepare(path)
        result = subprocess.run([bridge], input='\n'.join(j[0] for j in jobs) + '\n',
                                stdout=subprocess.PIPE, text=True, timeout=120)
        if result.returncode:
            print(f'FAIL: {filename} bridge exited with status {result.returncode}')
            return 1
        replies = result.stdout.splitlines()
        if len(replies) != len(jobs):
            print(f'FAIL: {filename} bridge response count mismatch')
            return 1
        for reply, (_, expected, label) in zip(replies, jobs):
            if reply != expected:
                print(f'FAIL: {label}: result mismatch')
                failures += 1
        total += len(jobs)
        print(f'{filename}: executed={len(jobs)}')
    print(f'nist: executed={total}, failures={failures}')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
