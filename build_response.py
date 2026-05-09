#!/usr/bin/env python3
"""
Build the response JSON file for the GitHub relay worker.

Reads status code, headers JSON, and encrypted body from separate files,
then writes the final JSON response – avoids passing huge strings as
command‑line arguments to jq (thus preventing "Argument list too long").

Usage:
    python3 build_response.py <status> <headers.json> <encrypted_body.txt> <output.json>

    <status>              HTTP status code (integer)
    <headers.json>        JSON file with response headers (as produced by parse_headers.py)
    <encrypted_body.txt>  single line containing the base64-encoded encrypted body
    <output.json>         where to write the final response JSON
"""
import sys
import json

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <status> <headers.json> <encrypted_body.txt> <output.json>",
              file=sys.stderr)
        sys.exit(1)

    status = int(sys.argv[1])
    headers_path = sys.argv[2]
    body_path = sys.argv[3]
    output_path = sys.argv[4]

    # Read headers
    with open(headers_path, "r", encoding="utf-8") as f:
        headers = json.load(f)

    # Read encrypted body (raw text)
    with open(body_path, "r", encoding="utf-8") as f:
        encrypted_body = f.read().strip()

    response = {
        "s": status,
        "b": encrypted_body,
        "h": headers,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(response, f)

if __name__ == "__main__":
    main()
