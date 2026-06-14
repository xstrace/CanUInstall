#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.parse
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from canuinstall.analyzer import analyze_path
from canuinstall.models import ASSESSMENT_CATALOG, CONTROL_ACTIONS, CONTROL_METHODS
from canuinstall.progress import JOBS, reset_reporter, set_reporter
from canuinstall.tart_dynamic import tart_readiness


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_UPLOAD = 2 * 1024 * 1024 * 1024
MAX_CONFIG_BODY = 16 * 1024
ENV_FILE = ROOT / ".env.local"

TOOL_GROUPS = [
    {
        "id": "core",
        "title": "核心静态分析工具",
        "items": [
            ("codesign", ["/usr/bin/codesign"], "代码签名、发布者、Entitlements 和运行时加固检查"),
            ("spctl", ["/usr/sbin/spctl"], "Gatekeeper 与公证接受状态检查"),
            ("pkgutil", ["/usr/sbin/pkgutil"], "PKG 展开、签名和安装脚本检查"),
            ("hdiutil", ["/usr/bin/hdiutil"], "DMG 只读挂载与内容检查"),
            ("ditto", ["/usr/bin/ditto"], "ZIP 安装包展开"),
            ("file", ["/usr/bin/file"], "Mach-O 架构识别"),
        ],
    },
    {
        "id": "enhanced",
        "title": "增强检测能力",
        "items": [
            ("clamscan", ["clamscan"], "本地已知恶意内容扫描；缺失时不会执行本地杀毒引擎"),
        ],
    },
    {
        "id": "tart",
        "title": "Tart 隔离动态分析",
        "items": [
            ("tart", ["/opt/homebrew/bin/tart", "tart"], "创建一次性 macOS VM 并执行隔离动态观察"),
            ("tart-base-vm", [], "可克隆的 Tart 基础 VM；优先使用 canuinstall-runtime"),
            ("osquery", [], "在 Tart VM 内每秒记录进程和打开的网络 socket"),
            ("eslogger", [], "在 Tart VM 内记录进程生命周期和文件变更事件"),
            ("tcpdump", [], "在 Tart VM 内记录 TCP 建连、UDP 和 DNS 数据包"),
            ("fs_usage", [], "在 Tart VM 内补充记录文件系统操作"),
            ("lsof", [], "在 Tart VM 内高频补充采样进程网络 socket"),
        ],
    },
]


def load_local_environment() -> None:
    path = ENV_FILE
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip("\"'"))


load_local_environment()


def resolve_tool(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate.startswith("/") and Path(candidate).is_file():
            return candidate
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def environment_status() -> dict[str, object]:
    groups = []
    missing_effects = []
    tart = tart_readiness()
    for group in TOOL_GROUPS:
        items = []
        for tool_id, candidates, effect in group["items"]:
            if tool_id == "tart-base-vm":
                path = str(tart["baseVm"]) if tart["baseVmAvailable"] else None
            elif tool_id == "osquery":
                path = (
                    "Tart VM: /usr/local/bin/osqueryi"
                    if tart["osqueryExpected"]
                    else None
                )
            elif tool_id in {"eslogger", "tcpdump", "fs_usage", "lsof"}:
                guest_paths = {
                    "eslogger": "/usr/bin/eslogger",
                    "tcpdump": "/usr/sbin/tcpdump",
                    "fs_usage": "/usr/bin/fs_usage",
                    "lsof": "/usr/sbin/lsof",
                }
                path = (
                    f"Tart VM: {guest_paths[tool_id]}"
                    if tart["baseVmAvailable"]
                    else None
                )
            else:
                path = resolve_tool(candidates)
            items.append(
                {
                    "id": tool_id,
                    "available": bool(path),
                    "path": path or "",
                    "effect": effect,
                }
            )
            if not path:
                missing_effects.append({"id": tool_id, "effect": effect})
        groups.append({"id": group["id"], "title": group["title"], "items": items})
    vt_configured = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    if not vt_configured:
        missing_effects.append(
            {
                "id": "virustotal",
                "effect": "无法查询 VirusTotal 已有的多引擎哈希报告；其他本地检查仍可运行",
            }
        )
    return {
        "platform": "macOS" if shutil.which("codesign") else "unsupported",
        "virusTotalConfigured": vt_configured,
        "tart": tart,
        "groups": groups,
        "missingEffects": missing_effects,
    }


def save_local_api_key(path: Path, api_key: str | None) -> None:
    values: dict[str, str] = {}
    if path.is_file():
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in raw_line or raw_line.lstrip().startswith("#"):
                continue
            name, value = raw_line.split("=", 1)
            values[name.strip()] = value.strip()
    if api_key:
        values["VIRUSTOTAL_API_KEY"] = api_key
    else:
        values.pop("VIRUSTOTAL_API_KEY", None)
    if not values:
        path.unlink(missing_ok=True)
        return
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        "".join(f"{name}={value}\n" for name, value in sorted(values.items())),
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


class Handler(BaseHTTPRequestHandler):
    server_version = "CanUInstall/0.1"

    def do_GET(self) -> None:
        parsed_request = urllib.parse.urlparse(self.path)
        path = parsed_request.path
        files = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        if path == "/api/status":
            self.send_json(environment_status())
            return
        if path == "/api/environment":
            self.send_json(environment_status())
            return
        if path == "/api/capabilities":
            self.send_json(
                {
                    "groups": [
                        {
                            "id": group["id"],
                            "title": group["title"],
                            "items": [
                                {
                                    "id": control_id,
                                    "title": title,
                                    "method": CONTROL_METHODS.get(control_id, ""),
                                    "action": CONTROL_ACTIONS.get(
                                        control_id,
                                        "不适用（当前结论不需要额外处理）。",
                                    ),
                                }
                                for control_id, title in group["items"]
                            ],
                        }
                        for group in ASSESSMENT_CATALOG
                    ]
                }
            )
            return
        if path.startswith("/api/jobs/"):
            job_id = path.removeprefix("/api/jobs/")
            job = JOBS.get(job_id)
            if not job:
                self.send_json({"error": "任务不存在或已过期。"}, HTTPStatus.NOT_FOUND)
                return
            query = urllib.parse.parse_qs(parsed_request.query)
            try:
                since = int(query.get("since", ["0"])[0])
            except ValueError:
                since = 0
            self.send_json(job.snapshot(since))
            return
        if path not in files:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        filename, content_type = files[path]
        body = (STATIC / filename).read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path == "/api/config":
            self.update_config()
            return
        if self.path != "/api/analyze":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD:
            self.send_json({"error": "请求为空或文件超过 2 GB。"}, HTTPStatus.BAD_REQUEST)
            return

        workdir = Path(tempfile.mkdtemp(prefix="canuinstall-"))
        try:
            form = self.parse_multipart(length)
            upload = form.get("file")
            homepage = field_text(form.get("homepage"))
            dynamic_enabled = field_text(form.get("dynamic")) == "true"

            if upload and upload.get_content():
                filename = safe_filename(upload.get_filename() or "upload.bin")
                target = workdir / filename
                target.write_bytes(upload.get_payload(decode=True))
                source = {"type": "file", "name": filename}
            else:
                shutil.rmtree(workdir, ignore_errors=True)
                self.send_json({"error": "请选择要分析的安装包。"}, HTTPStatus.BAD_REQUEST)
                return
            if homepage:
                source["homepage"] = homepage

            job = JOBS.create()
            job.log("任务已创建，等待分析线程。", "info", "system")
            if target:
                job.log(
                    f"上传接收完成：{target.name}（{target.stat().st_size / 1024 / 1024:.1f} MB）",
                    "success",
                    "upload",
                )
            threading.Thread(
                target=run_analysis_job,
                args=(
                    job,
                    workdir,
                    target,
                    source,
                    dynamic_enabled,
                ),
                daemon=True,
                name=f"analysis-{job.id[:8]}",
            ).start()
            self.send_json(
                {"jobId": job.id, "status": "queued"},
                HTTPStatus.ACCEPTED,
            )
        except Exception as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            self.log_error("analysis failed: %r", exc)
            self.send_json(
                {"error": f"分析失败：{exc.__class__.__name__}: {exc}"},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def update_config(self) -> None:
        try:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                self.send_json(
                    {"error": "配置接口只接受本机请求。"},
                    HTTPStatus.FORBIDDEN,
                )
                return
        except ValueError:
            self.send_json({"error": "无法确认请求来源。"}, HTTPStatus.FORBIDDEN)
            return
        origin = self.headers.get("Origin", "")
        if origin:
            parsed_origin = urllib.parse.urlparse(origin)
            try:
                origin_is_local = ipaddress.ip_address(
                    parsed_origin.hostname or ""
                ).is_loopback
            except ValueError:
                origin_is_local = parsed_origin.hostname == "localhost"
            if not origin_is_local:
                self.send_json(
                    {"error": "拒绝来自其他网页的配置请求。"},
                    HTTPStatus.FORBIDDEN,
                )
                return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_CONFIG_BODY:
            self.send_json({"error": "配置请求无效。"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json({"error": "配置内容不是有效 JSON。"}, HTTPStatus.BAD_REQUEST)
            return
        clear = payload.get("clearVirusTotal") is True
        api_key = str(payload.get("virusTotalApiKey", "")).strip()
        if not clear and not re.fullmatch(r"[A-Fa-f0-9]{64}", api_key):
            self.send_json(
                {"error": "VirusTotal API Key 应为 64 位十六进制字符串。"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        save_local_api_key(ENV_FILE, None if clear else api_key)
        if clear:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
        else:
            os.environ["VIRUSTOTAL_API_KEY"] = api_key
        self.send_json(
            {
                "saved": True,
                "virusTotalConfigured": not clear,
                "message": "VirusTotal 配置已清除。" if clear else "VirusTotal API Key 已保存在本机。",
            }
        )

    def parse_multipart(self, length: int) -> dict[str, object]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("Content-Type 必须是 multipart/form-data")
        raw = self.rfile.read(length)
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + raw
        )
        result: dict[str, object] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name:
                result[name] = part
        return result

    def send_json(self, payload: object, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[web] {self.address_string()} {fmt % args}")


def field_text(part: object | None) -> str:
    if part is None:
        return ""
    return str(part.get_content()).strip()


def safe_filename(name: str) -> str:
    return Path(name.replace("\\", "/")).name or "upload.bin"


def run_analysis_job(
    job,
    workdir: Path,
    target: Path,
    source: dict[str, object],
    dynamic_enabled: bool,
) -> None:
    token = set_reporter(job.log)
    with job.lock:
        job.status = "running"
    started = time.time()
    try:
        job.log("分析线程已启动。", "success", "system")
        report = analyze_path(
            target,
            source=source,
            workdir=workdir,
            vt_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            dynamic_enabled=dynamic_enabled,
            tart_base_vm=os.getenv("TART_BASE_VM"),
        )
        job.log(f"任务完成，总耗时 {time.time() - started:.1f}s。", "success", "system")
        with job.lock:
            job.report = report
            job.status = "completed"
            job.updated_at = time.time()
    except Exception as exc:
        job.log(f"分析失败：{exc.__class__.__name__}: {exc}", "error", "system")
        with job.lock:
            job.error = f"{exc.__class__.__name__}: {exc}"
            job.status = "failed"
            job.updated_at = time.time()
    finally:
        reset_reporter(token)
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="macOS software admission checker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"CanUInstall is running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
