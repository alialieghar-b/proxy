#!/usr/bin/env python3
"""
github_api_worker.py – lightweight relay worker using only the GitHub REST API.

Eliminates all git operations. The worker runs in an endless loop:
1. List queue/ directory (ALL pages), pick the oldest file.
2. Download encrypted request via API.
3. Decrypt, fetch the real URL, encrypt the response.
4. PUT the encrypted response file (with retry on 409), DELETE the queue file.

Authentication: GITHUB_TOKEN environment variable (provided by Actions).
Encryption key: ENCRYPTION_KEY env var (same 64‑char hex string as the addon).

Required environment variables:
    GITHUB_REPO       owner/repo
    GITHUB_TOKEN      GitHub personal access token or Actions token
    ENCRYPTION_KEY    64‑character hex key (AES‑GCM)
    BRANCH            branch to operate on (default: relay)
"""
import os
import sys
import json
import base64
import time
import traceback

import requests

# ------------------------------------------------------------------ helpers
def _env(key, default=None):
    v = os.environ.get(key, default)
    if v is None:
        print(f"ERROR: missing required env var {key}", file=sys.stderr)
        sys.exit(1)
    return v

REPO = _env("GITHUB_REPO").strip().rstrip("/")
TOKEN = _env("GITHUB_TOKEN")
ENC_KEY_HEX = _env("ENCRYPTION_KEY")
BRANCH = _env("BRANCH", "relay")

API_BASE = f"https://api.github.com/repos/{REPO}"
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "gh-relay-worker/1.0",
}

# ------------------------------------------------------------------ encryption (same logic as addon)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

_key = bytes.fromhex(ENC_KEY_HEX)
_aead = AESGCM(_key)

def encrypt(plain: bytes) -> str:
    nonce = os.urandom(12)
    ct = _aead.encrypt(nonce, plain, None)
    return base64.b64encode(nonce + ct).decode()

def decrypt(enc: str) -> bytes:
    raw = base64.b64decode(enc)
    nonce, ct = raw[:12], raw[12:]
    return _aead.decrypt(nonce, ct, None)

# ------------------------------------------------------------------ hop‑by‑hop filter
HOP_BY_HOP = {
    "host", "proxy-connection", "content-length",
    "connection", "transfer-encoding", "te", "trailer",
    "upgrade", "proxy-authorization", "proxy-authenticate",
}

def filter_headers(headers: dict) -> dict:
    """Remove hop‑by‑hop headers and Accept‑Encoding (so requests can handle decompression properly)."""
    cleaned = {}
    for k, v in headers.items():
        lower = k.lower()
        if lower in HOP_BY_HOP or lower == "accept-encoding":
            continue
        cleaned[k] = v
    return cleaned

# ------------------------------------------------------------------ GitHub API
def api_get(path, **kwargs):
    """GET a GitHub API endpoint, return parsed JSON."""
    url = f"{API_BASE}/contents/{path}?ref={BRANCH}"
    resp = requests.get(url, headers=HEADERS, **kwargs)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise Exception(f"GET {path}: {resp.status_code} {resp.text}")
    return resp.json()

def api_list_dir(path):
    """
    List directory contents by fetching ALL pages.
    Returns a list of {name, ...} dicts.
    """
    entries = []
    page = 1
    while True:
        url = f"{API_BASE}/contents/{path}?ref={BRANCH}&page={page}&per_page=100"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise Exception(f"LIST {path} page {page}: {resp.status_code} {resp.text}")
        data = resp.json()
        if not isinstance(data, list):
            return [data]
        if not data:
            break  # no more entries
        entries.extend(data)
        # Check if there's a next page via Link header
        link = resp.headers.get("Link", "")
        if 'rel="next"' not in link:
            break
        page += 1
    return entries

def put_file_safe(path, content_str, message, retries=3):
    """
    Create or update a file.  If a 409 conflict occurs,
    re-fetch the SHA and retry.
    """
    url = f"{API_BASE}/contents/{path}"
    for attempt in range(1, retries + 1):
        # Get current SHA if file already exists, otherwise None
        existing = api_get(path)
        sha = existing["sha"] if existing is not None else None
        payload = {
            "message": message,
            "content": base64.b64encode(content_str.encode("utf-8")).decode("utf-8"),
            "branch": BRANCH,
        }
        if sha:
            payload["sha"] = sha
        resp = requests.put(url, headers=HEADERS, json=payload)
        if resp.status_code in (200, 201):
            return resp.json()
        elif resp.status_code == 409:
            print(f"⚠️ PUT {path} conflict, retrying ({attempt}/{retries})")
            time.sleep(0.5)
        else:
            raise Exception(f"PUT {path}: {resp.status_code} {resp.text}")
    raise Exception(f"PUT {path}: failed after {retries} retries")

def delete_file_safe(path, message, retries=3):
    """Delete a file by path, with SHA re‑fetch on 409."""
    for attempt in range(1, retries + 1):
        info = api_get(path)
        if info is None:
            return  # already gone
        sha = info["sha"]
        url = f"{API_BASE}/contents/{path}"
        payload = {
            "message": message,
            "sha": sha,
            "branch": BRANCH,
        }
        resp = requests.delete(url, headers=HEADERS, json=payload)
        if resp.status_code in (200, 204):
            return
        elif resp.status_code == 409:
            print(f"⚠️ DELETE {path} conflict, retrying ({attempt}/{retries})")
            time.sleep(0.5)
        else:
            raise Exception(f"DELETE {path}: {resp.status_code} {resp.text}")
    raise Exception(f"DELETE {path}: failed after {retries} retries")

# ------------------------------------------------------------------ worker loop
def worker_loop():
    print("🚀 API worker started")
    while True:
        try:
            # 1. List ALL queue/ directory entries
            entries = api_list_dir("queue")
            if not entries:
                time.sleep(2)
                continue

            # Pick oldest file (alphabetical order = chronological order)
            entries.sort(key=lambda e: e["name"])
            oldest = entries[0]
            queue_name = oldest["name"]
            queue_path = f"queue/{queue_name}"
            response_path = f"response/{queue_name}"

            # ★ If response already exists, just delete the queue file and skip
            existing_resp = api_get(response_path)
            if existing_resp is not None:
                print(f"--> Response already exists for {queue_name}, removing queue file only")
                delete_file_safe(queue_path, f"Remove already-processed {queue_name}")
                continue

            # 2. Download & decrypt request
            file_info = api_get(queue_path)
            if file_info is None:
                continue
            raw_content = base64.b64decode(file_info["content"]).decode("utf-8")
            envelope = json.loads(raw_content)
            enc_payload = envelope["e"]
            req_json = decrypt(enc_payload)
            req = json.loads(req_json)

            req_id = req.get("id", "")
            method = req.get("method", "GET")
            url = req.get("url", "")
            headers = filter_headers(req.get("headers", {}))
            body_b64 = req.get("body_base64") or ""

            if not url:
                print(f"!! Skipping malformed request {queue_name}")
                delete_file_safe(queue_path, f"Malformed request {queue_name}")
                continue

            print(f"==> Processing {queue_name}: {method} {url}")

            # 3. Fetch the real URL
            try:
                if body_b64 and body_b64 != "null":
                    body_data = base64.b64decode(body_b64)
                else:
                    body_data = None

                fetch_resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body_data,
                    timeout=30,
                    allow_redirects=True,
                )
                http_code = fetch_resp.status_code
                resp_body = fetch_resp.content
                resp_headers = dict(fetch_resp.headers)
            except Exception as e:
                print(f"!! Fetch failed for {queue_name}: {e}")
                http_code = 502
                resp_body = b""
                resp_headers = {}

            # 4. Build response
            enc_body = encrypt(resp_body)
            response_dict = {
                "s": http_code,
                "b": enc_body,
                "h": resp_headers,
            }
            response_str = json.dumps(response_dict)

            # 5. PUT response file safely (retries on 409)
            try:
                put_file_safe(response_path, response_str, f"Processed {queue_name}")
            except Exception as e:
                print(f"!! Failed to PUT response for {queue_name}: {e}")
                delete_file_safe(queue_path, f"Failed to create response {queue_name}")
                continue

            # 6. DELETE queue file safely
            try:
                delete_file_safe(queue_path, f"Remove processed {queue_name}")
            except Exception as e:
                print(f"!! Failed to DELETE queue file {queue_name}: {e}")

            print(f"--> Done {queue_name}")

        except KeyboardInterrupt:
            print("\nWorker stopped.")
            break
        except Exception:
            print(f"!! Worker loop error: {traceback.format_exc()}")
            time.sleep(5)

if __name__ == "__main__":
    worker_loop()
