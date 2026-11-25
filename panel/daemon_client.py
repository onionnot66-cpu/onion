"""Authenticated HTTP client for Panel <-> Node Agent communication."""

import json
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from panel.security import sign_daemon_request


class DaemonClient:
    """Signs and sends authenticated requests to an OMCP ONION Node Agent."""

    def __init__(self, node: Dict[str, Any], timeout: float = 30.0) -> None:
        scheme = node.get("node_scheme") or node.get("scheme") or "http"
        host = node.get("node_ip") or node.get("ip_address") or node.get("fqdn")
        port = node.get("daemon_port", 8443)
        self.base_url = f"{scheme}://{host}:{port}"
        self.token = node["daemon_token"]
        self.timeout = timeout

    def _headers(self, method: str, path: str, body: bytes = b"", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        ts = str(int(time.time()))
        sig = sign_daemon_request(self.token, method, path, ts, body)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Onion-Timestamp": ts,
            "X-Onion-Signature": sig,
        }
        if extra:
            headers.update(extra)
        return headers

    def request(
        self,
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        raw_bytes: Optional[bytes] = None,
        content_type: Optional[str] = None,
    ) -> Any:
        body_bytes = b""
        extra_headers: Dict[str, str] = {}
        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            extra_headers["Content-Type"] = "application/json"
        elif raw_bytes is not None:
            body_bytes = raw_bytes
            if content_type:
                extra_headers["Content-Type"] = content_type

        headers = self._headers(method, path, body_bytes, extra_headers)
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=self.timeout, verify=False) as client:
                resp = client.request(method, url, content=body_bytes if body_bytes else None, params=params, headers=headers)
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Node agent unreachable at {self.base_url}: {exc}",
            )

        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text or f"Node agent returned HTTP {resp.status_code}"
            raise HTTPException(status_code=resp.status_code if resp.status_code < 500 else 502, detail=detail)

        if "application/json" in resp.headers.get("content-type", ""):
            return resp.json()
        return resp.content

    def download(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bytes, str]:
        headers = self._headers("GET", path, b"")
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=60.0, verify=False) as client:
                resp = client.get(url, params=params, headers=headers)
        except httpx.RequestError as exc:
            raise HTTPException(status_code=503, detail=f"Node agent unreachable: {exc}")
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise HTTPException(status_code=resp.status_code, detail=detail)
        return resp.content, resp.headers.get("content-type", "application/octet-stream")

    def upload_file(self, server_id: str, directory: str, filename: str, data: bytes) -> Dict[str, Any]:
        path = f"/agent/servers/{server_id}/files/upload"
        params = {"directory": directory, "filename": filename}
        return self.request("POST", path, params=params, raw_bytes=data, content_type="application/octet-stream")

    def ws_console_url(self, server_id: str) -> str:
        ws_scheme = "wss" if self.base_url.startswith("https://") else "ws"
        host_port = self.base_url.split("://", 1)[1]
        return f"{ws_scheme}://{host_port}/agent/servers/{server_id}/console/ws?token={quote(self.token)}"
