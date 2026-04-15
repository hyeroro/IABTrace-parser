import os
import re
import sys
import struct
import datetime
from urllib.parse import urlparse, parse_qs


# ---------------- WebKit Timestamp Conversion ----------------

def webkit_to_datetime(microseconds):
    try:
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=microseconds)
    except:
        return None


# ---------------- Entry Header Timestamp Extraction ----------------

def extract_timestamp(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)

            if len(header) < 32:
                return None

            raw = struct.unpack("<Q", header[24:32])[0]

            if raw < 100000000000000:
                return None

            return webkit_to_datetime(raw)

    except:
        return None


# ---------------- URL & Keyword Extraction ----------------

URL_REGEX = re.compile(rb"https?://[^\s\"']+")
SEARCH_PATTERN = b"search?q="


def extract_search_artifacts(file_path):

    artifacts = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if SEARCH_PATTERN not in data:
            return []

        urls = URL_REGEX.findall(data)

        for raw_url in urls:
            if SEARCH_PATTERN in raw_url:

                url = raw_url.decode(errors="ignore")
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                keyword = params.get("q", [None])[0]
                timestamp = extract_timestamp(file_path)

                artifacts.append({
                    "file_name": os.path.basename(file_path),
                    "full_path": file_path,
                    "url": url,
                    "keyword": keyword,
                    "timestamp": timestamp
                })

    except Exception as e:
        print(f"[!] Error processing {file_path}: {e}")

    return artifacts


# ---------------- Cache Directory Automatic Navigation ----------------

def find_cache_directory(base_dir):

    for root, dirs, files in os.walk(base_dir):
        if "cache" in root.lower() and "cache_data" in root.lower():
            return root

    return None


# ---------------- Cache Directory Analysis ----------------

def analyze_cache_directory(cache_dir):

    print("[+] Cache folder found:", cache_dir)

    results = []

    for root, dirs, files in os.walk(cache_dir):
        for file in files:
            file_path = os.path.join(root, file)
            artifacts = extract_search_artifacts(file_path)

            if artifacts:
                results.extend(artifacts)

    return results


# ---------------- Printing Results ----------------

def print_results(results):

    if not results:
        print("[!] No search artifacts found")
        return

    print("\n[+] Search Artifacts Found:", len(results))
    print("---------------------------------------------------")

    for r in results:
        print("File      :", r["file_name"])
        print("Keyword   :", r["keyword"])
        print("Timestamp :", r["timestamp"])
        print("URL       :", r["url"])
        print("---------------------------------------------------")


# ---------------- Main Analysis Entry ----------------

def run_analysis(base_dir: str):

    if not os.path.exists(base_dir):
        print("[!] Base directory does not exist:", base_dir)
        return

    cache_dir = find_cache_directory(base_dir)

    if not cache_dir:
        print("[!] Cache folder not found.")
        return

    results = analyze_cache_directory(cache_dir)
    print_results(results)

    return results


# ---------------- Standalone Execution ----------------

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 cache_parser.py <base_directory>")
        sys.exit(1)

    base_directory = sys.argv[1]
    run_analysis(base_directory)
