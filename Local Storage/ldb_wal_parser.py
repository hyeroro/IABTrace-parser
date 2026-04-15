#!/usr/bin/env python3
"""
LevelDB WAL → IndexedDB Key/Value Extractor
Common Parser Module
"""

import os
import struct
from enum import IntEnum
from typing import List, Dict
from datetime import datetime


# ---------------- Record Type ----------------

class RecordType(IntEnum):
    ZERO_TYPE = 0
    FULL_TYPE = 1
    FIRST_TYPE = 2
    MIDDLE_TYPE = 3
    LAST_TYPE = 4
    EOF = 5
    BAD_RECORD = 6


# ---------------- LevelDB Log Parser ----------------

class LevelDBLogParser:
    BLOCK_SIZE = 32768
    HEADER_SIZE = 7

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.buffer = b''
        self.eof = False

    def __enter__(self):
        self.file = open(self.filepath, 'rb')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def read_physical_record(self):
        while True:
            if len(self.buffer) < self.HEADER_SIZE:
                if self.eof:
                    return RecordType.EOF, b''
                self.buffer = self.file.read(self.BLOCK_SIZE)
                if len(self.buffer) == 0:
                    self.eof = True
                    return RecordType.EOF, b''

            header = self.buffer[:7]
            length = struct.unpack('<H', header[4:6])[0]
            rtype = header[6]

            if self.HEADER_SIZE + length > len(self.buffer):
                self.buffer = b''
                return RecordType.BAD_RECORD, b''

            data = self.buffer[7:7 + length]
            self.buffer = self.buffer[7 + length:]

            try:
                return RecordType(rtype), data
            except ValueError:
                return RecordType.BAD_RECORD, b''

    def read_records(self):
        records = []
        scratch = bytearray()
        in_frag = False

        while True:
            rtype, frag = self.read_physical_record()

            if rtype == RecordType.FULL_TYPE:
                records.append(bytes(frag))

            elif rtype == RecordType.FIRST_TYPE:
                scratch = bytearray(frag)
                in_frag = True

            elif rtype == RecordType.MIDDLE_TYPE and in_frag:
                scratch.extend(frag)

            elif rtype == RecordType.LAST_TYPE and in_frag:
                scratch.extend(frag)
                records.append(bytes(scratch))
                in_frag = False

            elif rtype == RecordType.EOF:
                break

        return records


# ---------------- WriteBatch Parser ----------------

def read_varint(data: bytes, offset: int):
    result = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, offset


def parse_write_batch(batch: bytes):
    results = []

    seq = struct.unpack('<Q', batch[:8])[0]
    count = struct.unpack('<I', batch[8:12])[0]
    offset = 12

    for _ in range(count):
        op_type = batch[offset]
        offset += 1

        key_len, offset = read_varint(batch, offset)
        key = batch[offset:offset + key_len]
        offset += key_len

        if op_type == 1:  # PUT
            val_len, offset = read_varint(batch, offset)
            value = batch[offset:offset + val_len]
            offset += val_len
        else:
            value = None

        results.append({
            "sequence": seq,
            "op": "PUT" if op_type == 1 else "DEL",
            "key_raw": key,
            "value_raw": value
        })

    return results


# ---------------- IndexedDB Decoder ----------------

def decode_indexeddb_key(key: bytes):
    try:
        return key.decode('utf-8', errors='ignore')
    except Exception:
        return repr(key)


def decode_indexeddb_value(value: bytes):
    if not value:
        return ""
    try:
        # Chromium Local Storage Encoding: [0] UTF-16LE, [1] Latin-1 (Extended ASCII)
        prefix = value[0]
        if prefix == 0:  # UTF-16LE
            return value[1:].decode('utf-16-le', errors='ignore')
        elif prefix == 1:  # Latin-1 (Extended ASCII)
            return value[1:].decode('iso-8859-1', errors='ignore')
        else:
            return value.decode('utf-8', errors='ignore')
    except Exception:
        return repr(value)


# ---------------- Search Query Extractor ----------------

def extract_search_queries(all_kv: List[Dict]) -> List[Dict]:
    search_results = []

    for i, kv in enumerate(all_kv):
        key = kv.get('key', '')
        value = kv.get('value', '')
        if not value: continue

        # 1. google search keyward (sb_wiz.pq) + timestamp (sb_wiz.pq_tm_hp)
        if 'sb_wiz.pq' in key and 'sb_wiz.pq_tm_hp' not in key:
            query = value.strip()
            # Adjacent record search logic
            timestamp = "[No Timestamp]"
            for j in range(i + 1, min(i + 10, len(all_kv))):
                next_kv = all_kv[j]
                if 'sb_wiz.pq_tm_hp' in next_kv.get('key', ''):
                    raw_ts = next_kv.get('value', '').strip()
                    try:
                        if raw_ts.isdigit():
                            ts_val = int(raw_ts)
                            dt = datetime.fromtimestamp(ts_val / 1000) if ts_val > 10**12 else datetime.fromtimestamp(ts_val)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except: pass
                    break
            
            search_results.append({
                'timestamp': timestamp,
                'query': f"[Google Search] {query}",
                'source': 'Google'
            })

        # 2. System log timestamp information (glad_loader)
        elif 'glad_loader' in key and '"regDate":"' in value:
            try:
                reg_date = value.split('"regDate":"')[1].split('"')[0]
                search_results.append({
                    'timestamp': reg_date,
                    'query': "[System Log] Policy Updated",
                    'source': 'System'
                })
            except: pass

    return search_results


# ---------------- Main Runner ----------------

def run_analysis(base_dir: str):
    leveldb_dir = None

    for d in os.listdir(base_dir):
        if "leveldb" in d.lower():
            leveldb_dir = os.path.join(base_dir, d)
            break

    if not leveldb_dir:
        print("[!] LevelDB folder not found.")
        return

    print(f"[+] LevelDB folder found: {leveldb_dir}")

    wal_files = [f for f in os.listdir(leveldb_dir) if f.endswith(".log")]

    if not wal_files:
        print("[!] WAL files (.log) not found")
        return

    all_kv = []

    for fname in wal_files:
        log_file = os.path.join(leveldb_dir, fname)
        print(f"\n[*] Parsing WAL: {log_file}")

        with LevelDBLogParser(log_file) as parser:
            records = parser.read_records()

        print(f"[+] Physical records: {len(records)}")

        for rec in records:
            try:
                entries = parse_write_batch(rec)
                for e in entries:
                    key = decode_indexeddb_key(e["key_raw"])
                    val = decode_indexeddb_value(e["value_raw"]) if e["value_raw"] else None

                    all_kv.append({
                        "sequence": e["sequence"],
                        "op": e["op"],
                        "key": key,
                        "value": val
                    })
            except Exception:
                continue

    print("\n" + "=" * 80)
    print("--- SUMMARY ---")
    print("=" * 80)
    print(f"Total KV: {len(all_kv)}")

    search_queries = extract_search_queries(all_kv)

    if search_queries:
        print(f"\n[+] Search Queries Found: {len(search_queries)}")
        print("-" * 80)
        print(f"{'No.':<5} {'Timestamp':<22} {'Search Query'}")
        print("-" * 80)

        for idx, sq in enumerate(search_queries, 1):
            query_display = (
                sq['query'][:50] + '...' if len(sq['query']) > 50 else sq['query']
            )
            print(f"{idx:<5} {sq['timestamp']:<22} {query_display}")
    else:
        print("\n[!] No search queries found in WAL file")
    return search_queries

# python your_script.py /path/to/data
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <base_directory>")
        sys.exit(1)

    base_dir = sys.argv[1]
    run_analysis(base_dir)
