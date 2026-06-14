from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .dynamic_behavior import build_behavior_summary
from .progress import emit


TART_LOCK = threading.Lock()
SECTION_PATTERN = re.compile(
    r"^===CANUINSTALL:([A-Z_]+)===\n(.*?)(?=^===CANUINSTALL:|\Z)",
    re.M | re.S,
)


@dataclass
class TartObservation:
    status: str
    summary: str
    vm_name: str = ""
    launched: bool = False
    executable: str = ""
    bundle_id: str = ""
    behavior: dict[str, object] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    collectors: list[str] = field(default_factory=list)
    raw_output: str = ""

    def as_metadata(self) -> dict[str, object]:
        return {
            "status": self.status,
            "summary": self.summary,
            "vmName": self.vm_name,
            "launched": self.launched,
            "executable": self.executable,
            "bundleId": self.bundle_id,
            "behavior": self.behavior,
            "logs": self.logs,
            "collectors": self.collectors,
        }


def tart_path() -> str | None:
    return shutil.which("tart") or (
        "/opt/homebrew/bin/tart" if Path("/opt/homebrew/bin/tart").is_file() else None
    )


def local_tart_vms(tart: str | None = None) -> list[dict[str, object]]:
    executable = tart or tart_path()
    if not executable:
        return []
    try:
        result = subprocess.run(
            [executable, "list", "--source", "local", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return []
        import json

        payload = json.loads(result.stdout)
        return payload if isinstance(payload, list) else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def tart_readiness(base_vm: str | None = None) -> dict[str, object]:
    executable = tart_path()
    vms = local_tart_vms(executable)
    names = [str(item.get("Name", "")) for item in vms]
    selected = (
        base_vm
        or os.getenv("TART_BASE_VM")
        or ("canuinstall-runtime" if "canuinstall-runtime" in names else "tahoe-base")
    )
    return {
        "tartPath": executable or "",
        "baseVm": selected,
        "baseVmAvailable": selected in names,
        "localVms": names,
        "ready": bool(executable and selected in names),
        "networkMode": "softnet",
        "osqueryExpected": selected == "canuinstall-runtime",
    }


def observe_with_tart(
    sample: Path,
    workdir: Path,
    *,
    base_vm: str | None = None,
    duration: int = 20,
) -> TartObservation:
    readiness = tart_readiness(base_vm)
    if not readiness["ready"]:
        return TartObservation(
            "not_run",
            f"Tart 或基础 VM {readiness['baseVm']} 不可用。",
        )
    if sample.suffix.lower() == ".pkg":
        return TartObservation(
            "not_run",
            "PKG 需要安装交互和管理员授权，当前不会自动安装执行。",
        )

    executable = str(readiness["tartPath"])
    selected_vm = str(readiness["baseVm"])
    vm_name = f"canuinstall-{uuid.uuid4().hex[:10]}"
    shared_sample = sample
    try:
        sample.resolve().relative_to(workdir.resolve())
    except ValueError:
        shared_sample = workdir / sample.name
        emit("将样本暂存到 Tart 只读共享目录。", "info", "step")
        if sample.is_dir():
            shutil.copytree(sample, shared_sample, dirs_exist_ok=True)
        else:
            shutil.copy2(sample, shared_sample)
    script = workdir / "tart-observe.sh"
    script.write_text(
        _guest_script(shared_sample.name, max(8, min(duration, 120))),
        encoding="utf-8",
    )
    script.chmod(0o755)
    run_process: subprocess.Popen[str] | None = None

    emit(f"等待 Tart 动态观察锁：基础镜像 {selected_vm}", "info", "step")
    with TART_LOCK:
        try:
            emit(f"创建一次性 VM：{vm_name}", "info", "phase")
            cloned = _run([executable, "clone", selected_vm, vm_name], timeout=180)
            if cloned.returncode != 0:
                return TartObservation(
                    "failed",
                    "无法克隆 Tart 基础 VM。",
                    vm_name=vm_name,
                    raw_output=cloned.output,
                )

            share = f"canuinstall:{workdir}:ro"
            command = [
                executable,
                "run",
                "--no-graphics",
                "--no-audio",
                "--no-clipboard",
                "--net-softnet",
                f"--dir={share}",
                "--root-disk-opts=sync=none",
                vm_name,
            ]
            emit("$ " + " ".join(shlex.quote(item) for item in command), "command", "command")
            run_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            ready = _wait_for_guest(executable, vm_name, run_process, timeout=120)
            if ready.returncode != 0:
                run_output = _process_output(run_process)
                detail = "\n".join(part for part in (ready.output, run_output) if part)
                return TartObservation(
                    "failed",
                    "Tart VM 未在时限内启动或 Guest Agent 不可用。",
                    vm_name=vm_name,
                    raw_output=detail,
                )

            emit(
                f"VM Guest Agent 已就绪，开始 {duration} 秒隔离观察。",
                "success",
                "result",
            )
            guest = _run(
                [
                    executable,
                    "exec",
                    vm_name,
                    "/bin/zsh",
                    "/Volumes/My Shared Files/canuinstall/tart-observe.sh",
                ],
                timeout=duration + 90,
            )
            sections = _parse_sections(guest.output)
            launched = sections.get("LAUNCH_STATUS", "").strip() == "launched"
            summary = (
                "应用已在一次性 Tart VM 中启动并完成观察。"
                if launched and guest.returncode == 0
                else "动态观察已运行，但应用未成功启动或观察脚本返回异常。"
            )
            identified_executable = sections.get("EXECUTABLE", "").strip()
            identified_bundle_id = sections.get("BUNDLE_ID", "").strip()
            return TartObservation(
                "completed" if launched and guest.returncode == 0 else "partial",
                summary,
                vm_name=vm_name,
                launched=launched,
                executable=identified_executable,
                bundle_id=identified_bundle_id,
                behavior=build_behavior_summary(
                    sections,
                    executable=identified_executable,
                    bundle_id=identified_bundle_id,
                    duration=max(8, min(duration, 120)),
                ),
                logs=_lines(sections.get("LOGS", ""), 30),
                collectors=_lines(sections.get("COLLECTORS", ""), 10),
                raw_output=guest.output[-12000:],
            )
        finally:
            emit(f"停止并删除一次性 VM：{vm_name}", "info", "phase")
            _run([executable, "stop", vm_name, "--timeout", "5"], timeout=15)
            if run_process and run_process.poll() is None:
                run_process.terminate()
                try:
                    run_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    run_process.kill()
            _run([executable, "delete", vm_name], timeout=60)


def _run(args: list[str], *, timeout: int) -> "DynamicCommandResult":
    emit("$ " + " ".join(shlex.quote(item) for item in args), "command", "command")
    started = time.monotonic()
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        emit(
            f"exit {result.returncode} · {time.monotonic() - started:.2f}s"
            + (f"\n{output[-4000:]}" if output else ""),
            "success" if result.returncode == 0 else "warning",
            "output",
        )
        return DynamicCommandResult(result.returncode, result.stdout, result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        emit(f"动态命令失败：{exc}", "error", "output")
        return DynamicCommandResult(124, "", str(exc))


def _wait_for_guest(
    executable: str,
    vm_name: str,
    process: subprocess.Popen[str],
    *,
    timeout: int,
) -> "DynamicCommandResult":
    emit("等待 Tart VM 启动并连接 Guest Agent。", "info", "step")
    deadline = time.monotonic() + timeout
    last_error = ""
    attempts = 0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return DynamicCommandResult(
                process.returncode or 1,
                "",
                _process_output(process) or "tart run 已提前退出。",
            )
        attempts += 1
        try:
            probe = subprocess.run(
                [executable, "exec", vm_name, "/usr/bin/true"],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            if probe.returncode == 0:
                emit(f"Guest Agent 就绪（第 {attempts} 次探测）。", "success", "result")
                return DynamicCommandResult(0, "ready", "")
            last_error = "\n".join(
                part for part in (probe.stdout, probe.stderr) if part
            ).strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc)
        time.sleep(3)
    return DynamicCommandResult(124, "", last_error or "等待 Guest Agent 超时。")


@dataclass
class DynamicCommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr) if part).strip()


def _parse_sections(output: str) -> dict[str, str]:
    return {name: value.strip() for name, value in SECTION_PATTERN.findall(output)}


def _lines(value: str, limit: int) -> list[str]:
    return list(dict.fromkeys(line.strip() for line in value.splitlines() if line.strip()))[:limit]


def _process_output(process: subprocess.Popen[str] | None) -> str:
    if not process or process.poll() is None or not process.stdout:
        return ""
    try:
        return process.stdout.read().strip()
    except OSError:
        return ""


def _guest_script(sample_name: str, duration: int) -> str:
    sample_path = shlex.quote(f"/Volumes/My Shared Files/canuinstall/{sample_name}")
    return f"""#!/bin/zsh
set -u
SAMPLE={sample_path}
ROOT="/tmp/canuinstall-dynamic"
MOUNT="$ROOT/mount"
EXPANDED="$ROOT/expanded"
APP=""
mkdir -p "$ROOT" "$MOUNT" "$EXPANDED"

case "${{SAMPLE:l}}" in
  *.dmg)
    hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$MOUNT" "$SAMPLE" >/tmp/cui-hdiutil.txt 2>&1 || true
    APP=$(find "$MOUNT" -maxdepth 3 -name '*.app' -type d 2>/dev/null | head -1)
    ;;
  *.zip)
    ditto -x -k "$SAMPLE" "$EXPANDED" >/tmp/cui-ditto.txt 2>&1 || true
    APP=$(find "$EXPANDED" -maxdepth 4 -name '*.app' -type d 2>/dev/null | head -1)
    ;;
  *.app)
    APP="$SAMPLE"
    ;;
esac

if [[ -z "$APP" ]]; then
  print '===CANUINSTALL:LAUNCH_STATUS==='
  print 'not-launched'
  print '===CANUINSTALL:LOGS==='
  print '未在样本中找到可启动的 .app'
  exit 3
fi

LOCAL_APP="$ROOT/${{APP:t}}"
ditto "$APP" "$LOCAL_APP" >/tmp/cui-copy.txt 2>&1 || true
EXECUTABLE=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$LOCAL_APP/Contents/Info.plist" 2>/dev/null || true)
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$LOCAL_APP/Contents/Info.plist" 2>/dev/null || true)
print -r -- "$EXECUTABLE" > "$ROOT/executable"
sleep 5
touch "$ROOT/observation-started"

/usr/bin/log stream --style compact --level info --predicate "process == '$EXECUTABLE'" > "$ROOT/runtime.log" 2>&1 &
LOG_PID=$!

OSQUERY_BIN=$(command -v osqueryi 2>/dev/null || true)
OSQUERY_PID=""
if [[ -n "$OSQUERY_BIN" ]]; then
  (
    while true; do
      NOW=$(date +%s)
      print "@$NOW" >> "$ROOT/osquery-processes.log"
      "$OSQUERY_BIN" --config_path=/dev/null --disable_events=true --json \
        "select pid,parent,name,path,cmdline,start_time from processes;" \
        >> "$ROOT/osquery-processes.log" 2>> "$ROOT/osquery-errors.log"
      print "@$NOW" >> "$ROOT/osquery-sockets.log"
      "$OSQUERY_BIN" --config_path=/dev/null --disable_events=true --json \
        "select pid,path,protocol,local_address,remote_address,local_port,remote_port,state from process_open_sockets where remote_port > 0;" \
        >> "$ROOT/osquery-sockets.log" 2>> "$ROOT/osquery-errors.log"
      sleep 1
    done
  ) &
  OSQUERY_PID=$!
  print 'osquery: 每秒记录进程和打开的网络 socket' > "$ROOT/collectors"
else
  print 'osquery: 未安装，进程与 socket 快照缺失' > "$ROOT/collectors"
fi

sudo -n /usr/bin/eslogger --format json \
  exec fork exit create copyfile link rename unlink truncate setmode setowner setflags \
  > "$ROOT/es-events.log" 2> "$ROOT/eslogger-errors.log" &
ES_PID=$!
print 'eslogger: EndpointSecurity 进程与文件变更事件' >> "$ROOT/collectors"

sudo -n /usr/bin/fs_usage -w -f filesys > "$ROOT/fs-usage.log" 2>&1 &
FS_PID=$!
print 'fs_usage: 文件操作回退记录' >> "$ROOT/collectors"

sudo -n /usr/sbin/tcpdump -l -tt -vv -n -i any \
  '(tcp[tcpflags] & tcp-syn != 0) or udp' \
  > "$ROOT/network-packets.log" 2> "$ROOT/tcpdump-errors.log" &
PACKET_PID=$!
print 'tcpdump: TCP 建连、UDP 与 DNS 数据包' >> "$ROOT/collectors"

(
  while true; do
    print "@$(date +%s)" >> "$ROOT/lsof-sockets.log"
    /usr/sbin/lsof -nP -i -FpcnPT >> "$ROOT/lsof-sockets.log" 2>/dev/null || true
    sleep 0.5
  done
) &
LSOF_PID=$!
print 'lsof: 高频 socket 状态补充采样' >> "$ROOT/collectors"

LAUNCH_TIME=$(date +%s)
open -n "$LOCAL_APP" >/tmp/cui-open.txt 2>&1
OPEN_STATUS=$?
sleep {duration}

PIDS=$(pgrep -x "$EXECUTABLE" 2>/dev/null | paste -sd, -)
kill "$LOG_PID" >/dev/null 2>&1 || true
sudo -n kill "$FS_PID" >/dev/null 2>&1 || true
sudo -n kill "$ES_PID" >/dev/null 2>&1 || true
sudo -n kill "$PACKET_PID" >/dev/null 2>&1 || true
kill "$OSQUERY_PID" >/dev/null 2>&1 || true
kill "$LSOF_PID" >/dev/null 2>&1 || true
sleep 1

print '===CANUINSTALL:LAUNCH_STATUS==='
if [[ "$OPEN_STATUS" -eq 0 ]]; then print 'launched'; else print 'not-launched'; fi
print '===CANUINSTALL:EXECUTABLE==='
print -r -- "$EXECUTABLE"
print '===CANUINSTALL:BUNDLE_ID==='
print -r -- "$BUNDLE_ID"
print '===CANUINSTALL:LAUNCH_TIME==='
print -r -- "$LAUNCH_TIME"
print '===CANUINSTALL:OSQUERY_PROCESSES==='
cat "$ROOT/osquery-processes.log" 2>/dev/null | tail -6000
print '===CANUINSTALL:OSQUERY_SOCKETS==='
cat "$ROOT/osquery-sockets.log" 2>/dev/null | tail -4000
print '===CANUINSTALL:ES_EVENTS==='
cat "$ROOT/es-events.log" 2>/dev/null | tail -5000
print '===CANUINSTALL:NETWORK_PACKETS==='
cat "$ROOT/network-packets.log" 2>/dev/null | tail -4000
print '===CANUINSTALL:LSOF_SOCKETS==='
cat "$ROOT/lsof-sockets.log" 2>/dev/null | tail -6000
print '===CANUINSTALL:FS_EVENTS==='
cat "$ROOT/fs-usage.log" 2>/dev/null | tail -5000
print '===CANUINSTALL:RECENT_FILES==='
for TARGET in \
  "$HOME/Library/Containers/$BUNDLE_ID" \
  "$HOME/Library/Application Support/$EXECUTABLE" \
  "$HOME/Library/Caches/$BUNDLE_ID" \
  "$HOME/Library/Logs/$EXECUTABLE" \
  "$HOME/Library/Preferences/$BUNDLE_ID.plist"; do
  [[ -e "$TARGET" ]] && find "$TARGET" -type f -newer "$ROOT/observation-started" 2>/dev/null
done | sort -u | head -60
print '===CANUINSTALL:LOGS==='
tail -40 "$ROOT/runtime.log"
print '===CANUINSTALL:COLLECTORS==='
cat "$ROOT/collectors"
print '===CANUINSTALL:COLLECTOR_WARNINGS==='
cat "$ROOT/osquery-errors.log" "$ROOT/eslogger-errors.log" "$ROOT/tcpdump-errors.log" 2>/dev/null | tail -80

pkill -x "$EXECUTABLE" >/dev/null 2>&1 || true
hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true
exit 0
"""
