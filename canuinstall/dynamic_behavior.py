from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any


PROCESS_EVENT_NAMES = {"exec", "fork", "exit"}
FILE_EVENT_ACTIONS = {
    "create": "create",
    "copyfile": "create",
    "link": "create",
    "rename": "rename",
    "unlink": "delete",
    "truncate": "modify",
    "setmode": "modify",
    "setowner": "modify",
    "setflags": "modify",
}
FS_OPERATION_ACTIONS = {
    "mkdir": "create",
    "mkdirat": "create",
    "rename": "rename",
    "renameat": "rename",
    "unlink": "delete",
    "unlinkat": "delete",
    "rmdir": "delete",
    "truncate": "modify",
    "ftruncate": "modify",
    "write": "modify",
    "pwrite": "modify",
    "writev": "modify",
    "chmod": "modify",
    "chown": "modify",
    "setattrlist": "modify",
}
FS_LINE_PATTERN = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<operation>\S+).*?\s{2,}(?P<path>/.*?)\s+"
    r"\d+\.\d+\s+(?P<process>.+?)\.(?P<pid>\d+)$"
)
TCPDUMP_DNS_QUERY = re.compile(
    r"\b(?P<type>A|AAAA|CNAME|MX|NS|PTR|SRV|TXT)\?\s+"
    r"(?P<domain>[A-Za-z0-9_.-]+)\.?(?:\s|\()"
)
TCPDUMP_DNS_ANSWER = re.compile(
    r"(?P<domain>[A-Za-z0-9_.-]+)\.\s+(?:\d+\s+)?A\s+"
    r"(?P<address>(?:\d{1,3}\.){3}\d{1,3})"
)
HOST_PORT_V4 = re.compile(r"^(?P<host>.+)\.(?P<port>\d+)$")
HOST_PORT_V6 = re.compile(r"^(?P<host>[0-9a-fA-F:]+)\.(?P<port>\d+)$")


def build_behavior_summary(
    sections: dict[str, str],
    *,
    executable: str,
    bundle_id: str,
    duration: int,
) -> dict[str, object]:
    launch_time = _to_int(sections.get("LAUNCH_TIME"))
    processes = _collect_processes(
        sections.get("OSQUERY_PROCESSES", ""),
        sections.get("ES_EVENTS", ""),
    )
    family = _process_family(processes, executable, launch_time)
    family_pids = {item["pid"] for item in family}
    process_names = {item["pid"]: item["name"] for item in family}

    connections = _collect_connections(
        sections.get("OSQUERY_SOCKETS", ""),
        sections.get("LSOF_SOCKETS", ""),
        family_pids,
        process_names,
    )
    dns_queries = _collect_dns_queries(
        sections.get("NETWORK_PACKETS", ""),
        family,
        connections,
    )
    _attach_domains_to_connections(connections, dns_queries, family)
    file_activities = _collect_file_activities(
        sections.get("ES_EVENTS", ""),
        sections.get("FS_EVENTS", ""),
        sections.get("RECENT_FILES", ""),
        family_pids,
        process_names,
        executable,
        bundle_id,
    )
    file_counts = Counter(item["action"] for item in file_activities)
    warnings = _collector_warnings(sections.get("COLLECTOR_WARNINGS", ""))

    return {
        "durationSeconds": duration,
        "processCount": len(family),
        "processTree": _render_process_tree(family),
        "processes": family,
        "connectionCount": len(connections),
        "connections": connections,
        "domainCount": len(dns_queries),
        "dnsQueries": dns_queries,
        "fileActivityCount": len(file_activities),
        "fileOperationCounts": dict(sorted(file_counts.items())),
        "fileActivities": file_activities,
        "warnings": warnings,
    }


def _collect_processes(
    osquery_snapshots: str,
    es_events: str,
) -> list[dict[str, object]]:
    processes: dict[int, dict[str, object]] = {}

    def add(
        pid: object,
        ppid: object = 0,
        *,
        name: object = "",
        path: object = "",
        cmdline: object = "",
        event: str = "observed",
        timestamp: object = 0,
        start_time: object = 0,
    ) -> None:
        process_id = _to_int(pid)
        if process_id <= 0:
            return
        parent_id = _to_int(ppid)
        event_time = _to_int(timestamp)
        started = _to_int(start_time)
        item = processes.setdefault(
            process_id,
            {
                "pid": process_id,
                "ppid": parent_id,
                "name": "",
                "path": "",
                "cmdline": "",
                "events": set(),
                "firstSeen": event_time or started,
                "lastSeen": event_time or started,
                "startTime": started,
            },
        )
        if parent_id and not item["ppid"]:
            item["ppid"] = parent_id
        item["name"] = str(name or item["name"])
        item["path"] = str(path or item["path"])
        item["cmdline"] = str(cmdline or item["cmdline"])
        item["events"].add(event)
        seen = event_time or started
        if seen:
            current_first = _to_int(item["firstSeen"])
            item["firstSeen"] = min(current_first, seen) if current_first else seen
            item["lastSeen"] = max(_to_int(item["lastSeen"]), seen)
        if started:
            item["startTime"] = started

    for timestamp, rows in _snapshot_blocks(osquery_snapshots):
        for row in rows:
            add(
                row.get("pid"),
                row.get("parent"),
                name=row.get("name"),
                path=row.get("path"),
                cmdline=row.get("cmdline"),
                timestamp=timestamp,
                start_time=row.get("start_time"),
            )

    for payload in _json_lines(es_events):
        event_name, event_data = _endpoint_event(payload)
        actor = payload.get("process", {})
        actor_pid = _process_pid(actor)
        actor_ppid = _process_parent_pid(actor)
        actor_path = _process_path(actor)
        actor_name = PurePosixPath(actor_path).name if actor_path else ""
        timestamp = _event_timestamp(payload)

        if event_name == "exec":
            target = event_data.get("target", {}) if isinstance(event_data, dict) else {}
            target_path = _process_path(target)
            args = event_data.get("args", []) if isinstance(event_data, dict) else []
            add(
                _process_pid(target),
                actor_pid,
                name=PurePosixPath(target_path).name if target_path else "",
                path=target_path,
                cmdline=" ".join(str(value) for value in args),
                event="exec",
                timestamp=timestamp,
            )
        elif event_name == "fork":
            child = event_data.get("child", {}) if isinstance(event_data, dict) else {}
            child_path = _process_path(child)
            add(
                _process_pid(child),
                actor_pid,
                name=PurePosixPath(child_path).name if child_path else actor_name,
                path=child_path,
                event="fork",
                timestamp=timestamp,
            )
        elif event_name == "exit":
            add(
                actor_pid,
                actor_ppid,
                name=actor_name,
                path=actor_path,
                event="exit",
                timestamp=timestamp,
            )

    result = []
    for item in processes.values():
        normalized = dict(item)
        normalized["events"] = sorted(item["events"])
        if not normalized["name"]:
            normalized["name"] = PurePosixPath(str(normalized["path"])).name or f"pid-{item['pid']}"
        result.append(normalized)
    return sorted(result, key=lambda item: (_to_int(item["firstSeen"]), item["pid"]))


def _process_family(
    processes: list[dict[str, object]],
    executable: str,
    launch_time: int,
) -> list[dict[str, object]]:
    executable_lower = executable.lower()
    by_pid = {int(item["pid"]): item for item in processes}
    included = {
        int(item["pid"])
        for item in processes
        if _is_target_process(item, executable_lower, launch_time)
    }
    changed = True
    while changed:
        changed = False
        for item in processes:
            pid = int(item["pid"])
            if int(item.get("ppid", 0)) in included and pid not in included:
                included.add(pid)
                changed = True
    family = [dict(by_pid[pid]) for pid in by_pid if pid in included]
    for item in family:
        if (
            str(item.get("name", "")).lower() != executable_lower
            and f"/contents/macos/{executable_lower}"
            in str(item.get("cmdline", "")).lower()
        ):
            item["name"] = f"{executable} ({item.get('name', '解释器')})"
    return family


def _is_target_process(
    item: dict[str, object],
    executable_lower: str,
    launch_time: int,
) -> bool:
    if not executable_lower:
        return False
    name = str(item.get("name", "")).lower()
    path = str(item.get("path", "")).lower()
    cmdline = str(item.get("cmdline", "")).lower()
    matches = (
        name == executable_lower
        or path.endswith(f"/contents/macos/{executable_lower}")
        or f"/contents/macos/{executable_lower}" in cmdline
        or f"/{executable_lower}.app/" in path
        or f"/{executable_lower}.app/" in cmdline
    )
    if not matches:
        return False
    started = _to_int(item.get("startTime")) or _to_int(item.get("firstSeen"))
    return not launch_time or not started or started >= launch_time - 2


def _render_process_tree(processes: list[dict[str, object]]) -> str:
    if not processes:
        return "未捕获到目标应用进程。"
    by_pid = {int(item["pid"]): item for item in processes}
    children: dict[int, list[int]] = {}
    for item in processes:
        children.setdefault(int(item.get("ppid", 0)), []).append(int(item["pid"]))
    for values in children.values():
        values.sort(key=lambda pid: (_to_int(by_pid[pid].get("firstSeen")), pid))
    roots = [
        int(item["pid"])
        for item in processes
        if int(item.get("ppid", 0)) not in by_pid
    ]
    roots.sort(key=lambda pid: (_to_int(by_pid[pid].get("firstSeen")), pid))
    lines: list[str] = []

    def walk(pid: int, prefix: str, last: bool, root: bool = False) -> None:
        item = by_pid[pid]
        connector = "" if root else ("`-- " if last else "|-- ")
        cmdline = str(item.get("cmdline", "")).strip()
        label = f"{item['name']} [pid {pid}]"
        if cmdline and cmdline != item["name"]:
            label += f"  {cmdline[:160]}"
        lines.append(prefix + connector + label)
        child_pids = children.get(pid, [])
        next_prefix = prefix + ("" if root else ("    " if last else "|   "))
        for index, child_pid in enumerate(child_pids):
            walk(child_pid, next_prefix, index == len(child_pids) - 1)

    for index, root_pid in enumerate(roots):
        if index:
            lines.append("")
        walk(root_pid, "", True, root=True)
    return "\n".join(lines)


def _collect_connections(
    osquery_snapshots: str,
    lsof_snapshots: str,
    family_pids: set[int],
    process_names: dict[int, str],
) -> list[dict[str, object]]:
    aggregated: dict[tuple[object, ...], dict[str, object]] = {}
    for timestamp, rows in _snapshot_blocks(osquery_snapshots):
        for row in rows:
            pid = _to_int(row.get("pid"))
            if pid not in family_pids:
                continue
            remote_address = str(row.get("remote_address", "")).strip()
            remote_port = _to_int(row.get("remote_port"))
            if not remote_address or remote_address in {"0.0.0.0", "::"} or not remote_port:
                continue
            protocol = _protocol_name(row.get("protocol"))
            key = (pid, protocol, remote_address, remote_port)
            item = aggregated.setdefault(
                key,
                {
                    "process": process_names.get(pid, f"pid-{pid}"),
                    "pid": pid,
                    "protocol": protocol,
                    "remoteAddress": remote_address,
                    "remotePort": remote_port,
                    "states": set(),
                    "firstSeen": timestamp,
                    "lastSeen": timestamp,
                    "samples": 0,
                },
            )
            state = str(row.get("state", "")).strip()
            if state:
                item["states"].add(state)
            item["firstSeen"] = min(_to_int(item["firstSeen"]), timestamp)
            item["lastSeen"] = max(_to_int(item["lastSeen"]), timestamp)
            item["samples"] += 1

    for timestamp, row in _lsof_socket_rows(lsof_snapshots):
        pid = _to_int(row.get("pid"))
        if pid not in family_pids:
            continue
        remote_address = str(row.get("remoteAddress", ""))
        remote_port = _to_int(row.get("remotePort"))
        if not remote_address or not remote_port:
            continue
        protocol = str(row.get("protocol", "IP"))
        key = (pid, protocol, remote_address, remote_port)
        item = aggregated.setdefault(
            key,
            {
                "process": process_names.get(pid, str(row.get("process", f"pid-{pid}"))),
                "pid": pid,
                "protocol": protocol,
                "remoteAddress": remote_address,
                "remotePort": remote_port,
                "states": set(),
                "firstSeen": timestamp,
                "lastSeen": timestamp,
                "samples": 0,
            },
        )
        state = str(row.get("state", "")).strip()
        if state:
            item["states"].add(state)
        item["firstSeen"] = min(_to_int(item["firstSeen"]), timestamp)
        item["lastSeen"] = max(_to_int(item["lastSeen"]), timestamp)
        item["samples"] += 1

    result = []
    for item in aggregated.values():
        normalized = dict(item)
        normalized["states"] = sorted(item["states"])
        result.append(normalized)
    return sorted(
        result,
        key=lambda item: (
            str(item["process"]).lower(),
            str(item["remoteAddress"]),
            int(item["remotePort"]),
        ),
    )[:200]


def _collect_dns_queries(
    packet_log: str,
    processes: list[dict[str, object]],
    connections: list[dict[str, object]],
) -> list[dict[str, object]]:
    domains: dict[str, dict[str, object]] = {}
    for line in packet_log.splitlines():
        query = TCPDUMP_DNS_QUERY.search(line)
        if not query:
            continue
        domain = query.group("domain").rstrip(".").lower()
        if not domain or domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa"):
            continue
        item = domains.setdefault(
            domain,
            {"domain": domain, "types": set(), "addresses": set(), "count": 0},
        )
        item["types"].add(query.group("type"))
        item["count"] += 1
    for line in packet_log.splitlines():
        for answer in TCPDUMP_DNS_ANSWER.finditer(line):
            domain = answer.group("domain").rstrip(".").lower()
            if domain in domains:
                domains[domain]["addresses"].add(answer.group("address"))
    result = []
    command_text = "\n".join(str(item.get("cmdline", "")).lower() for item in processes)
    remote_addresses = {
        str(item.get("remoteAddress", "")) for item in connections
    }
    for item in domains.values():
        normalized = dict(item)
        normalized["types"] = sorted(item["types"])
        normalized["addresses"] = sorted(item["addresses"])
        domain = str(item["domain"])
        attributed = domain in command_text or bool(
            set(normalized["addresses"]) & remote_addresses
        )
        if attributed:
            normalized["attribution"] = (
                "进程命令行" if domain in command_text else "远程 IP 匹配"
            )
            result.append(normalized)
    return sorted(result, key=lambda item: str(item["domain"]))[:200]


def _attach_domains_to_connections(
    connections: list[dict[str, object]],
    dns_queries: list[dict[str, object]],
    processes: list[dict[str, object]],
) -> None:
    command_by_pid = {
        _to_int(item.get("pid")): str(item.get("cmdline", "")).lower()
        for item in processes
    }
    for connection in connections:
        remote = str(connection.get("remoteAddress", ""))
        command = command_by_pid.get(_to_int(connection.get("pid")), "")
        domains = []
        for query in dns_queries:
            domain = str(query.get("domain", ""))
            addresses = {str(value) for value in query.get("addresses", [])}
            if domain and (domain in command or remote in addresses):
                domains.append(domain)
        connection["domains"] = sorted(set(domains))


def _collect_file_activities(
    es_events: str,
    fs_events: str,
    recent_files: str,
    family_pids: set[int],
    process_names: dict[int, str],
    executable: str,
    bundle_id: str,
) -> list[dict[str, object]]:
    aggregated: dict[tuple[str, str, int], dict[str, object]] = {}

    def add(action: str, path: str, pid: int, process: str, timestamp: object = "") -> None:
        normalized_path = path.strip()
        if not normalized_path or not normalized_path.startswith("/"):
            return
        key = (action, normalized_path, pid)
        item = aggregated.setdefault(
            key,
            {
                "action": action,
                "path": normalized_path,
                "process": process or (f"pid-{pid}" if pid else "目标应用"),
                "pid": pid,
                "count": 0,
                "firstSeen": str(timestamp or ""),
                "lastSeen": str(timestamp or ""),
            },
        )
        item["count"] += 1
        if timestamp:
            if not item["firstSeen"]:
                item["firstSeen"] = str(timestamp)
            item["lastSeen"] = str(timestamp)

    for payload in _json_lines(es_events):
        event_name, event_data = _endpoint_event(payload)
        action = FILE_EVENT_ACTIONS.get(event_name)
        if not action:
            continue
        actor = payload.get("process", {})
        pid = _process_pid(actor)
        if pid not in family_pids:
            continue
        paths = _all_paths(event_data)
        leaf_paths = [
            path
            for path in paths
            if not any(
                other != path and other.startswith(path.rstrip("/") + "/")
                for other in paths
            )
        ]
        for path in leaf_paths:
            add(
                action,
                path,
                pid,
                process_names.get(pid, PurePosixPath(_process_path(actor)).name),
                _event_timestamp(payload),
            )

    for line in fs_events.splitlines():
        match = FS_LINE_PATTERN.match(line.strip())
        if not match:
            continue
        pid = _to_int(match.group("pid"))
        process = match.group("process").strip()
        if pid not in family_pids and executable.lower() not in process.lower():
            continue
        operation = match.group("operation").lower()
        action = FS_OPERATION_ACTIONS.get(operation)
        if not action and operation == "open" and "W" in line:
            action = "modify"
        if action:
            add(action, match.group("path"), pid, process, match.group("time"))

    if not aggregated:
        for path in recent_files.splitlines():
            if path.strip():
                add("modify", path.strip(), 0, executable)

    app_markers = {
        marker.lower()
        for marker in (executable, bundle_id)
        if marker
    }
    result = list(aggregated.values())
    result.sort(
        key=lambda item: (
            not any(marker in str(item["path"]).lower() for marker in app_markers),
            {"create": 0, "modify": 1, "rename": 2, "delete": 3}.get(
                str(item["action"]), 9
            ),
            str(item["path"]).lower(),
        )
    )
    return result[:300]


def _snapshot_blocks(value: str) -> list[tuple[int, list[dict[str, object]]]]:
    blocks: list[tuple[int, list[dict[str, object]]]] = []
    timestamp = 0
    lines: list[str] = []
    for line in value.splitlines():
        if line.startswith("@") and line[1:].strip().isdigit():
            if lines:
                blocks.append((timestamp, _json_array("\n".join(lines))))
            timestamp = _to_int(line[1:].strip())
            lines = []
        else:
            lines.append(line)
    if lines:
        blocks.append((timestamp, _json_array("\n".join(lines))))
    return blocks


def _json_array(value: str) -> list[dict[str, object]]:
    try:
        payload = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _json_lines(value: str) -> list[dict[str, object]]:
    result = []
    for line in value.splitlines():
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict):
            result.append(payload)
    return result


def _lsof_socket_rows(value: str) -> list[tuple[int, dict[str, object]]]:
    rows: list[tuple[int, dict[str, object]]] = []
    timestamp = 0
    pid = 0
    process = ""
    protocol = ""
    state = ""
    pending: dict[str, object] | None = None

    def flush() -> None:
        nonlocal pending
        if pending:
            pending["state"] = state
            rows.append((timestamp, pending))
            pending = None

    for line in value.splitlines():
        if line.startswith("@") and line[1:].strip().isdigit():
            flush()
            timestamp = _to_int(line[1:].strip())
            pid = 0
            process = ""
            protocol = ""
            state = ""
        elif line.startswith("p"):
            flush()
            pid = _to_int(line[1:])
        elif line.startswith("c"):
            process = line[1:].strip()
        elif line.startswith("P"):
            flush()
            protocol = line[1:].strip().upper()
        elif line.startswith("TST="):
            state = line[4:].strip()
        elif line.startswith("n") and "->" in line:
            flush()
            remote = line[1:].split("->", 1)[1].strip()
            remote_address, remote_port = _split_host_port(remote)
            if remote_address and remote_port and not _is_local_address(remote_address):
                pending = {
                    "pid": pid,
                    "process": process,
                    "protocol": protocol,
                    "remoteAddress": remote_address,
                    "remotePort": remote_port,
                }
                state = ""
    flush()
    return rows


def _endpoint_event(payload: dict[str, object]) -> tuple[str, dict[str, Any]]:
    event = payload.get("event", {})
    if isinstance(event, dict):
        for name, data in event.items():
            if name in PROCESS_EVENT_NAMES or name in FILE_EVENT_ACTIONS:
                return name, data if isinstance(data, dict) else {}
    event_name = str(payload.get("event_type", "")).lower()
    if event_name:
        return event_name, payload
    return "", {}


def _process_pid(process: object) -> int:
    if not isinstance(process, dict):
        return 0
    return _token_pid(process.get("audit_token")) or _to_int(process.get("pid"))


def _process_parent_pid(process: object) -> int:
    if not isinstance(process, dict):
        return 0
    return _token_pid(process.get("parent_audit_token")) or _to_int(process.get("parent"))


def _token_pid(token: object) -> int:
    return _to_int(token.get("pid")) if isinstance(token, dict) else 0


def _process_path(process: object) -> str:
    if not isinstance(process, dict):
        return ""
    executable = process.get("executable", {})
    if isinstance(executable, dict) and executable.get("path"):
        return str(executable["path"])
    return str(process.get("path", ""))


def _event_timestamp(payload: dict[str, object]) -> int:
    for key in ("time", "timestamp"):
        value = payload.get(key)
        if isinstance(value, (int, float, str)):
            parsed = _to_int(value)
            if parsed:
                return parsed
    return 0


def _all_paths(value: object) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        filename = value.get("filename")
        directory = value.get("dir") or value.get("directory")
        if isinstance(filename, str) and isinstance(directory, dict):
            directory_paths = _all_paths(directory)
            for directory_path in directory_paths:
                paths.append(str(PurePosixPath(directory_path) / filename))
        for key, nested in value.items():
            if key in {"path", "destination", "source"} and isinstance(nested, str):
                if nested.startswith("/"):
                    paths.append(nested)
            else:
                paths.extend(_all_paths(nested))
    elif isinstance(value, list):
        for nested in value:
            paths.extend(_all_paths(nested))
    return list(dict.fromkeys(paths))


def _protocol_name(value: object) -> str:
    protocol = _to_int(value)
    return {6: "TCP", 17: "UDP"}.get(protocol, str(value or "IP").upper())


def _split_host_port(value: str) -> tuple[str, int]:
    cleaned = value.rstrip(":")
    if cleaned.startswith("[") and "]:" in cleaned:
        host, port = cleaned[1:].rsplit("]:", 1)
        return host, _to_int(port)
    if cleaned.count(":") == 1:
        host, port = cleaned.rsplit(":", 1)
        return host, _to_int(port)
    match = HOST_PORT_V6.match(cleaned) if ":" in cleaned else HOST_PORT_V4.match(cleaned)
    if not match:
        return "", 0
    return match.group("host"), _to_int(match.group("port"))


def _is_local_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


def _collector_warnings(value: str) -> list[str]:
    ignored = (
        "data link type",
        "verbose output suppressed",
        "listening on ",
        "packets captured",
        "packets received by filter",
        "packets dropped by kernel",
    )
    return list(
        dict.fromkeys(
            line.strip()
            for line in value.splitlines()
            if line.strip()
            and not line.startswith("I")
            and not any(text in line.lower() for text in ignored)
        )
    )[:20]


def _to_int(value: object) -> int:
    try:
        return int(float(str(value or "0")))
    except (TypeError, ValueError):
        return 0
