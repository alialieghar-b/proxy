#!/usr/bin/env python3
"""
Parse the response headers file produced by curl -D and output JSON.
Ignores the HTTP status line and any malformed lines.
"""
import sys
import json

headers = {}
with open("resp_headers.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line or ":" not in line:
            # skip empty lines and the status line (e.g., HTTP/1.1 200 OK)
            continue
        key, _, value = line.partition(": ")
        if key:
            headers[key.lower()] = value

json.dump(headers, sys.stdout)
