#!/usr/bin/env python3
"""
github_api_worker.py – fast relay worker using the GitHub REST API.

- Parallel fetches of real URLs (thread pool, batch size 10).
- Responses are uploaded individually with safe retry; queue files are
  deleted after upload.  No more Git Data API atomic commits – avoids
  conflicts with auto‑merge workflows.
- Timeouts on every HTTP request so the worker never hangs.
- Line‑buffered output for real‑time logging in GitHub Actions.

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
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ------------------------------------------------------------------ force line‑buffered output for Actions
sys.stdout.reconfigure(line_buffering=True)

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
    "User-Agent": "gh-relay-worker/3.1",
}

# ------------------------------------------------------------------ session helpers with timeout
DEFAULT_TIMEOUT = 30   # seconds

def _request(method, url, **kwargs):
    """Wraps requests.request with a default timeout."""
    if "timeout" not in kwargs:
        kwargs["timeout"] = DEFAULT_TIMEOUT
    return requests.request(method, url, **kwargs)

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
    cleaned = {}
    for k, v in headers.items():
        lower = k.lower()
        if lower in HOP_BY_HOP or lower == "accept-encoding":
            continue
        cleaned[k] = v
    return cleaned

# ------------------------------------------------------------------ GitHub API helpers
def api_get(path, **kwargs):
    url = f"{API_BASE}/contents/{path}?ref={BRANCH}"
    resp = _request("GET", url, headers=HEADERS, **kwargs)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise Exception(f"GET {path}: {resp.status_code} {resp.text}")
    return resp.json()

def api_list_dir(path):
    """List all entries in a directory (paginated)."""
    entries = []
    page = 1
    while True:
        url = f"{API_BASE}/contents/{path}?ref={BRANCH}&page={page}&per_page=100"
        resp = _request("GET", url, headers=HEADERS)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise Exception(f"LIST {path} page {page}: {resp.status_code} {resp.text}")
        data = resp.json()
        if not isinstance(data, list):
            return [data]
        if not data:
            break
        entries.extend(data)
        if 'rel="next"' not in resp.headers.get("Link", ""):
            break
        page += 1
    return entries

# ------------------------------------------------------------------ safe single‑file upload / delete
def put_file_safe(path, content_str, message, retries=3):
    url = f"{API_BASE}/contents/{path}"
    for attempt in range(1, retries + 1):
        existing = api_get(path)
        sha = existing["sha"] if existing is not None else None
        payload = {
            "message": message,
            "content": base64.b64encode(content_str.encode("utf-8")).decode("utf-8"),
            "branch": BRANCH,
        }
        if sha:
            payload["sha"] = sha
        resp = _request("PUT", url, headers=HEADERS, json=payload)
        if resp.status_code in (200, 201):
            return
        elif resp.status_code == 409:
            print(f"⚠️ PUT {path} conflict, retry {attempt}/{retries}")
            time.sleep(0.5)
        else:
            raise Exception(f"PUT {path}: {resp.status_code}")
    raise Exception(f"PUT {path}: failed after retries")

def delete_file_safe(path, message, retries=3):
    for attempt in range(1, retries + 1):
        info = api_get(path)
        if info is None:
            return
        sha = info["sha"]
        url = f"{API_BASE}/contents/{path}"
        payload = {"message": message, "sha": sha, "branch": BRANCH}
        resp = _request("DELETE", url, headers=HEADERS, json=payload)
        if resp.status_code in (200, 204):
            return
        elif resp.status_code == 409:
            print(f"⚠️ DELETE {path} conflict, retry {attempt}/{retries}")
            time.sleep(0.5)
        else:
            raise Exception(f"DELETE {path}: {resp.status_code}")
    raise Exception(f"DELETE {path}: failed after retries")

# ------------------------------------------------------------------ fetch helper (executed in threads)
def fetch_real_url(method, url, headers, body_data):
    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body_data,
            timeout=30,
            allow_redirects=True,
        )
        return (resp.status_code, resp.content, dict(resp.headers))
    except Exception as e:
        print(f"  !! background fetch failed for {url}: {e}")
        return (502, b"", {})

# ------------------------------------------------------------------ worker loop
def worker_loop():
    print("🚀 Fast API worker started (parallel fetches + single‑file uploads)")
    print("💓 Initial heartbeat")
    last_heartbeat = time.time()
    empty_since = None

    while True:
        try:
            # 1. List all queue entries
            entries = api_list_dir("queue")
            if not entries:
                now = time.time()
                if empty_since is None:
                    empty_since = now
                if now - last_heartbeat > 60:
                    print("💓 Worker alive – queue is empty")
                    last_heartbeat = now
                time.sleep(0.5)
                continue

            empty_since = None
            entries.sort(key=lambda e: e["name"])
            # Take up to 10 oldest
            batch = entries[:10]
            reqs = []

            # 2. Download & decrypt all requests in the batch (serial, fast)
            for e in batch:
                queue_name = e["name"]
                queue_path = f"queue/{queue_name}"
                response_path = f"response/{queue_name}"

                # Skip if response already exists
                existing = api_get(response_path)
                if existing is not None:
                    print(f"--> Response already exists for {queue_name}, removing queue file")
                    reqs.append({"queue_name": queue_name, "skip": True})
                    continue

                file_info = api_get(queue_path)
                if file_info is None:
                    continue

                raw = base64.b64decode(file_info["content"]).decode("utf-8")
                env = json.loads(raw)
                enc_payload = env["e"]
                req_json = decrypt(enc_payload)
                req = json.loads(req_json)

                req_id = req.get("id", "")
                method = req.get("method", "GET")
                url = req.get("url", "")
                headers = filter_headers(req.get("headers", {}))
                body_b64 = req.get("body_base64") or ""

                if not url:
                    print(f"!! Malformed request {queue_name}, will delete")
                    reqs.append({"queue_name": queue_name, "malformed": True})
                    continue

                try:
                    body_data = base64.b64decode(body_b64) if body_b64 and body_b64 != "null" else None
                except Exception:
                    body_data = b""

                reqs.append({
                    "queue_name": queue_name,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body_data": body_data,
                })

            if not reqs:
                continue

            # Separate entries that need actual fetch
            to_fetch = [r for r in reqs if "method" in r]

            results = {}
            # 3. Parallel fetch for real requests (up to 10 threads)
            if to_fetch:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {
                        executor.submit(
                            fetch_real_url,
                            r["method"],
                            r["url"],
                            r["headers"],
                            r["body_data"],
                        ): r["queue_name"]
                        for r in to_fetch
                    }
                    for future in as_completed(futures):
                        qname = futures[future]
                        try:
                            code, body, resp_headers = future.result()
                        except Exception:
                            code, body, resp_headers = 502, b"", {}
                        results[qname] = (code, body, resp_headers)

            # 4. Upload responses and delete queue files (serial, safe)
            for r in reqs:
                qname = r["queue_name"]
                try:
                    if "skip" in r:
                        delete_file_safe(f"queue/{qname}", f"Remove already-processed {qname}")
                        print(f"--> Cleaned up already-processed {qname}")
                    elif "malformed" in r:
                        delete_file_safe(f"queue/{qname}", f"Remove malformed {qname}")
                        print(f"--> Removed malformed {qname}")
                    else:
                        code, body, resp_headers = results[qname]
                        enc_body = encrypt(body)
                        resp_obj = {"s": code, "b": enc_body, "h": resp_headers}
                        put_file_safe(f"response/{qname}", json.dumps(resp_obj), f"Processed {qname}")
                        delete_file_safe(f"queue/{qname}", f"Remove {qname}")
                        print(f"--> Done {qname}")
                except Exception as upload_err:
                    print(f"!! Failed to finalise {qname}: {upload_err}")

        except KeyboardInterrupt:
            print("\nWorker stopped.")
            break
        except Exception:
            print(f"!! Worker loop error: {traceback.format_exc()}")
            time.sleep(5)


if __name__ == "__main__":
    worker_loop()
