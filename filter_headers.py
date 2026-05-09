#!/usr/bin/env python3
"""
Filter request headers for curl.

Reads a JSON object of headers from a file,
removes hop‑by‑hop / proxy‑internal headers,
and writes one `Key: value` line per header to stdout or a file.

Usage:
    python3 filter_headers.py <input_json_file> [output_file]
"""
import json
import sys

HOP_BY_HOP = {
    "host", "proxy-connection", "content-length",
    "connection", "transfer-encoding", "te", "trailer",
    "upgrade", "proxy-authorization", "proxy-authenticate",
}

def filter_headers(input_path: str, output_path: str = None):
    with open(input_path, "r", encoding="utf-8") as f:
        headers = json.load(f)

    lines = []
    for key, value in headers.items():
        if key.lower() not in HOP_BY_HOP:
            lines.append(f"{key}: {value}")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    else:
        for line in lines:
            print(line)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <headers.json> [output.txt]", file=sys.stderr)
        sys.exit(1)
    in_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else None
    filter_headers(in_file, out_file)
