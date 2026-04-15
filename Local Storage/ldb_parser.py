import os
import io
import struct
import datetime
import re
from urllib.parse import unquote_plus

# --------- Snappy decompress -----------
def snappy_decompress(data: bytes) -> bytes:
    pos = 0
    length = 0
    shift = 0
    # 1. Decompress the original length (Varint)
    while True:
        if pos >= len(data): return bytes()
        c = data[pos]
        pos += 1
        length |= (c & 0x7f) << shift
        if not (c & 0x80):
            break
        shift += 7
        
    out = bytearray()
    # 2. Decompress the token loop
    while pos < len(data):
        c = data[pos]
        pos += 1
        op = c & 0x03

        if op == 0:  # Uncompressed literal
            lit_len = (c >> 2) + 1
            if lit_len > 60:
                extra_bytes = (c >> 2) - 59
                lit_len = 0
                for i in range(extra_bytes):
                    lit_len |= data[pos] << (8 * i)
                    pos += 1
                lit_len += 1
            out.extend(data[pos:pos+lit_len])
            pos += lit_len

        elif op == 1:  # 1-byte offset copy
            length_idx = ((c >> 2) & 0x07) + 4
            offset = ((c >> 5) << 8) | data[pos]
            pos += 1
            for _ in range(length_idx):
                out.append(out[len(out) - offset])

        elif op == 2:  # 2-byte offset copy
            length_idx = (c >> 2) + 1
            offset = data[pos] | (data[pos+1] << 8)
            pos += 2
            for _ in range(length_idx):
                out.append(out[len(out) - offset])

        elif op == 3:  # 4-byte offset copy
            length_idx = (c >> 2) + 1
            offset = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24)
            pos += 4
            for _ in range(length_idx):
                out.append(out[len(out) - offset])
                
    return bytes(out)
# ---------------------------------------------------------------------

def read_le_varint(stream):
    result = 0
    i = 0
    while True:
        raw = stream.read(1)
        if not raw:
            return None
        tmp = raw[0]
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result

def parse_block(raw_block):
    if len(raw_block) < 4:
        return []
    
    restart_count = struct.unpack("<I", raw_block[-4:])[0]
    restart_offset = len(raw_block) - (restart_count + 1) * 4
    
    stream = io.BytesIO(raw_block[:restart_offset])
    prev_key = b""
    records = []
    
    while stream.tell() < restart_offset:
        shared = read_le_varint(stream)
        if shared is None: break
        non_shared = read_le_varint(stream)
        value_len = read_le_varint(stream)
        
        if non_shared is None or value_len is None: break
        
        key = prev_key[:shared] + stream.read(non_shared)
        value = stream.read(value_len)
        prev_key = key
        
        records.append((key, value))
        
    return records

def extract_records_from_ldb(file_path):
    parsed_records = []
    
    with open(file_path, 'rb') as f:
        f.seek(-8, os.SEEK_END)
        magic = struct.unpack("<Q", f.read(8))[0]
        if magic != 0xdb4775248b80fb57:
            raise ValueError("It is not a valid LevelDB (.ldb) file.")
        
        f.seek(-48, os.SEEK_END)
        read_le_varint(f)
        read_le_varint(f)
        
        idx_offset = read_le_varint(f)
        idx_len = read_le_varint(f)
        
        f.seek(idx_offset)
        idx_raw = f.read(idx_len)
        idx_trailer = f.read(5)
        
        if idx_trailer[0] == 1:
            idx_raw = snappy_decompress(idx_raw)
            
        idx_entries = parse_block(idx_raw)
        
        for _, val in idx_entries:
            v_stream = io.BytesIO(val)
            data_offset = read_le_varint(v_stream)
            data_len = read_le_varint(v_stream)
            
            f.seek(data_offset)
            data_raw = f.read(data_len)
            d_trailer = f.read(5)

            # Decompressor call
            if d_trailer[0] == 1:
                try:
                    data_raw = snappy_decompress(data_raw)
                except Exception as e:
                    print(f"[!] Block decompression failed: {e}")
                    continue
                    
            data_entries = parse_block(data_raw)
            
            for k, v in data_entries:
                if len(k) >= 8:
                    suffix = struct.unpack("<Q", k[-8:])[0]
                    seq = suffix >> 8
                    val_type = suffix & 0xff
                    state = "DEL" if val_type == 0 else "PUT"
                    user_key = k[:-8]
                else:
                    seq = 0
                    state = "UNKNOWN"
                    user_key = k
                    
                parsed_records.append((state, seq, user_key, v))
                
    return parsed_records

def main():
    print("="*80)
    print(" LevelDB IAB Search Artifact Carver (Pure Python Edition) ".center(80))
    print("="*80)

    file_path = input("Enter .ldb file path: ").strip()
    file_path = file_path.strip("\"'")
    
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return

    print(f"\nAnalysis started: {os.path.basename(file_path)}")
    print("Target carving: In-app browser internal query cache & URL parameters\n")

    try:
        records = extract_records_from_ldb(file_path)
    except Exception as e:
        print(f"[-] Error occurred while analyzing the file: {e}")
        return
    
    total_kv = len(records)
    results = set()

    for state, seq, user_key, value in records:
        if state != "PUT": 
            continue

        # 1. Attempt to extract timestamp from key (e.g., map-2-hsb;;1770708254825)
        dt = "Unknown Timestamp"
        if b";;" in user_key:
            ts_str = user_key.split(b";;")[-1].decode('ascii', errors='ignore')
            try:
                ts_int = int(ts_str)
                dt = datetime.datetime.fromtimestamp(ts_int / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass

        # 2. Value decoding (Chrome LocalStorage Prefix rules)
        val_str = ""
        if len(value) > 1:
            if value[0] == 0:
                val_str = value[1:].decode('utf-16-le', errors='ignore')
            elif value[0] == 1:
                val_str = value[1:].decode('utf-8', errors='ignore')
            else:
                val_str = value.decode('utf-8', errors='ignore')

        # Remove null bytes that interfere with regex detection
        clean_str = val_str.replace('\x00', '')

        # 3-A. URL parameter query carving (?q=search_term)
        for match in re.finditer(r'[?&]q=([^&"\\]+)', clean_str):
            clean_query = unquote_plus(match.group(1))
            results.add((dt, clean_query))

        # 3-B. Cash Carving in JSON Array Type (e.g., {"Conspiracy in the Second Degree":["eob_...)
        for match in re.finditer(r'"([^"]+)"\s*:\s*\[\s*"eob_', clean_str):
            clean_query = unquote_plus(match.group(1))
            results.add((dt, clean_query))

    sorted_results = sorted(list(results), key=lambda x: x[0])

    # 4. result
    print("\n" + "="*80)
    print("--- SUMMARY ---")
    print("="*80)
    print(f"Total KV: {total_kv}\n")
    print(f"[+] Search Queries Found: {len(sorted_results)}")
    print("-" * 80)
    print(f"{'No.':<5} {'Timestamp':<25} {'Search Query'}")
    print("-" * 80)
    
    for idx, (ts, query_data) in enumerate(sorted_results, 1):
        display_query = query_data[:40] + "..." if len(query_data) > 40 else query_data
        print(f"{idx:<5} {ts:<25} {display_query}")
        
    print("-" * 80)

if __name__ == '__main__':
    main()
