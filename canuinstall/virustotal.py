from __future__ import annotations

import json
import urllib.error
import urllib.request


API = "https://www.virustotal.com/api/v3"


def request_json(
    url: str,
    api_key: str,
    *,
    data: bytes | None = None,
    content_type: str | None = None,
    method: str | None = None,
) -> tuple[int, dict]:
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"error": {"message": body.decode(errors="replace")}}
        return exc.code, payload


def lookup(sha256: str, api_key: str) -> dict:
    status, payload = request_json(f"{API}/files/{sha256}", api_key)
    return {"status": status, "payload": payload}
