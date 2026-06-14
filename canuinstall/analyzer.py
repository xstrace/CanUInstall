from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import tempfile
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from .commands import CommandResult, run
from .models import AnalysisContext
from .tart_dynamic import observe_with_tart
from .progress import emit
from . import virustotal


PRIVACY_KEYS = {
    "NSAccessibilityUsageDescription": ("辅助功能", "high", 10),
    "NSAppleEventsUsageDescription": ("控制其他应用", "medium", 6),
    "NSCameraUsageDescription": ("摄像头", "medium", 5),
    "NSMicrophoneUsageDescription": ("麦克风", "medium", 5),
    "NSScreenCaptureUsageDescription": ("屏幕录制", "high", 9),
    "NSDesktopFolderUsageDescription": ("桌面文件", "low", 2),
    "NSDocumentsFolderUsageDescription": ("文稿文件", "medium", 4),
    "NSDownloadsFolderUsageDescription": ("下载文件", "low", 2),
    "NSContactsUsageDescription": ("通讯录", "medium", 5),
    "NSCalendarsUsageDescription": ("日历", "medium", 4),
    "NSRemindersUsageDescription": ("提醒事项", "medium", 4),
    "NSLocationUsageDescription": ("位置", "medium", 4),
}

FILE_ACCESS_ENTITLEMENTS = {
    "com.apple.security.files.user-selected.read-only": (
        "可读取用户在文件选择器中明确选中的文件或文件夹",
        "read",
    ),
    "com.apple.security.files.user-selected.read-write": (
        "可读写用户在文件选择器中明确选中的文件或文件夹",
        "write",
    ),
    "com.apple.security.files.downloads.read-only": (
        "可读取 Downloads 目录",
        "read",
    ),
    "com.apple.security.files.downloads.read-write": (
        "可读写 Downloads 目录",
        "write",
    ),
    "com.apple.security.assets.pictures.read-only": (
        "可读取 Pictures 目录",
        "read",
    ),
    "com.apple.security.assets.pictures.read-write": (
        "可读写 Pictures 目录",
        "write",
    ),
    "com.apple.security.assets.music.read-only": (
        "可读取 Music 目录",
        "read",
    ),
    "com.apple.security.assets.music.read-write": (
        "可读写 Music 目录",
        "write",
    ),
    "com.apple.security.assets.movies.read-only": (
        "可读取 Movies 目录",
        "read",
    ),
    "com.apple.security.assets.movies.read-write": (
        "可读写 Movies 目录",
        "write",
    ),
}

FILE_EXCEPTION_ENTITLEMENTS = {
    "com.apple.security.temporary-exception.files.absolute-path.read-only":
        "绝对路径只读沙箱例外",
    "com.apple.security.temporary-exception.files.absolute-path.read-write":
        "绝对路径读写沙箱例外",
    "com.apple.security.temporary-exception.files.home-relative-path.read-only":
        "Home 相对路径只读沙箱例外",
    "com.apple.security.temporary-exception.files.home-relative-path.read-write":
        "Home 相对路径读写沙箱例外",
}

SENSITIVE_PATH_MARKERS = {
    b"/Library/Application Support/com.apple.TCC": "TCC 权限数据库",
    b"/Library/Mail": "邮件数据目录",
    b"/Library/Messages": "信息数据目录",
    b"/Library/Safari": "Safari 数据目录",
    b"/Library/Keychains": "钥匙串目录",
    b"/Documents/": "Documents 路径",
    b"/Desktop/": "Desktop 路径",
    b"/Downloads/": "Downloads 路径",
}

ENTITLEMENT_RULES = {
    "com.apple.security.app-sandbox": ("启用 App Sandbox", "info", 0),
    "com.apple.security.cs.disable-library-validation": (
        "允许加载非同一开发者签名的代码",
        "medium",
        6,
    ),
    "com.apple.security.cs.allow-jit": ("允许 JIT 动态代码", "low", 2),
    "com.apple.security.cs.allow-unsigned-executable-memory": (
        "允许未签名可执行内存",
        "high",
        10,
    ),
    "com.apple.security.get-task-allow": ("允许调试/附加进程", "high", 10),
    "com.apple.security.automation.apple-events": (
        "允许通过 Apple Events 控制其他应用",
        "medium",
        6,
    ),
    "com.apple.developer.system-extension.install": ("可安装系统扩展", "high", 10),
    "com.apple.developer.networking.networkextension": ("使用网络扩展", "high", 10),
    "com.apple.developer.driverkit": ("使用 DriverKit 驱动能力", "high", 12),
}

SCRIPT_RULES = [
    (re.compile(r"\bcurl\b[^|\n]{0,300}\|\s*(?:sh|bash|zsh)\b", re.I), "下载内容直接交给 Shell 执行", "critical", 30),
    (re.compile(r"\bwget\b[^|\n]{0,300}\|\s*(?:sh|bash|zsh)\b", re.I), "下载内容直接交给 Shell 执行", "critical", 30),
    (re.compile(r"\b(?:curl|wget)\b", re.I), "安装脚本会联网下载内容", "high", 12),
    (re.compile(r"/Library/LaunchDaemons|/Library/LaunchAgents|~/Library/LaunchAgents", re.I), "安装持久化启动项", "high", 12),
    (re.compile(r"\blaunchctl\b", re.I), "操作后台服务或启动项", "medium", 7),
    (re.compile(r"\b(?:spctl|csrutil)\b.*\bdisable\b", re.I), "尝试关闭 macOS 安全机制", "critical", 35),
    (re.compile(r"\bxattr\b.*-d.*com\.apple\.quarantine", re.I), "移除下载隔离属性", "high", 12),
    (re.compile(r"\bsecurity\b.*add-trusted-cert", re.I), "向系统添加受信任证书", "critical", 30),
    (re.compile(r"\bnetworksetup\b.*(?:proxy|dns)", re.I), "修改网络代理或 DNS", "high", 12),
    (re.compile(r"/etc/hosts", re.I), "修改 hosts 文件", "high", 12),
    (re.compile(r"\bchmod\b.*(?:[4-7][0-7]{3}|[ug]\+s)", re.I), "设置高权限或 SUID/SGID 文件", "high", 12),
    (re.compile(r"\bosascript\b", re.I), "执行 AppleScript 自动化", "medium", 5),
]

PERSISTENCE_NAMES = {
    "LaunchAgents": ("包含 LaunchAgent", "medium", 7),
    "LaunchDaemons": ("包含 LaunchDaemon", "high", 10),
    "PrivilegedHelperTools": ("包含特权辅助程序", "high", 12),
    "SystemExtensions": ("包含系统扩展", "high", 12),
    "Extensions": ("包含扩展组件", "medium", 6),
    "LoginItems": ("包含登录项", "medium", 6),
}

RUNTIME_MARKERS = {
    "Electron Framework.framework": "Electron",
    "Chromium Embedded Framework.framework": "Chromium Embedded Framework",
    "QtCore.framework": "Qt",
    "Python.framework": "Python",
    "libnode.dylib": "Node.js",
    "JavaVM.framework": "Java",
}

UPDATE_MARKERS = {
    "Sparkle.framework": "Sparkle",
    "Squirrel.framework": "Squirrel",
    "ShipIt": "ShipIt",
    "KSUpdateEngine": "Google Update Engine",
}

DEPENDENCY_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "Podfile.lock",
}

STATIC_BINARY_RULES = [
    (b"DYLD_INSERT_LIBRARIES", "引用 DYLD 代码注入机制", "high", 10),
    (b"task_for_pid", "引用跨进程任务控制 API", "medium", 6),
    (b"CGEventTapCreate", "引用全局键盘/鼠标事件监听 API", "medium", 6),
    (b"SecKeychainFindGenericPassword", "引用钥匙串密码读取 API", "medium", 7),
    (b"add-trusted-cert", "包含添加系统信任证书命令", "high", 12),
    (b"com.apple.quarantine", "包含隔离属性处理逻辑", "low", 2),
]

SENSITIVE_DATA_MARKERS = {
    b"NSPasteboard": "剪贴板读取或写入 API",
    b"CGEventTapCreate": "全局键盘或鼠标事件监听 API",
    b"AXUIElement": "辅助功能与界面自动化 API",
    b"ScreenCaptureKit": "屏幕捕获框架",
    b"CGWindowListCreateImage": "窗口或屏幕图像捕获 API",
    b"AVCaptureDevice": "摄像头或麦克风采集 API",
    b"SecKeychainFindGenericPassword": "钥匙串凭据读取 API",
    b"SecItemCopyMatching": "钥匙串项目查询 API",
    b"CNContactStore": "通讯录访问 API",
    b"EKEventStore": "日历或提醒事项访问 API",
    b"CLLocationManager": "位置数据访问 API",
}

DATA_TRANSMISSION_MARKERS = {
    b"uploadTaskWithRequest": "HTTP 上传任务 API",
    b"NSURLSessionWebSocketTask": "WebSocket 长连接",
    b"URLSession": "网络请求 API",
    b"grpc": "gRPC 网络通信组件",
    b"CloudKit": "Apple CloudKit 云同步",
    b"CKContainer": "Apple CloudKit 容器",
    b"AWSS3": "Amazon S3 客户端",
    b"GoogleDrive": "Google Drive 集成",
    b"Dropbox": "Dropbox 集成",
}

LOCAL_STORAGE_MARKERS = {
    b"sqlite3_open": "SQLite 本地数据库",
    b"CoreData": "Core Data 本地存储",
    b"NSUserDefaults": "UserDefaults 配置存储",
    b"Realm": "Realm 本地数据库",
}

ENCRYPTION_MARKERS = {
    b"CryptoKit": "CryptoKit",
    b"CommonCrypto": "CommonCrypto",
    b"CCCrypt": "CommonCrypto 加解密 API",
    b"SecKeychain": "macOS Keychain",
    b"SQLCipher": "SQLCipher 加密数据库",
}

TELEMETRY_MARKERS = {
    "Sentry.framework": "Sentry",
    "SentryCrash": "Sentry Crash",
    "FirebaseAnalytics": "Firebase Analytics",
    "FirebaseCrashlytics": "Firebase Crashlytics",
    "Crashlytics.framework": "Crashlytics",
    "Amplitude": "Amplitude",
    "Mixpanel": "Mixpanel",
    "Segment": "Segment",
    "Datadog": "Datadog",
    "NewRelic": "New Relic",
    "Bugly": "Bugly",
}


def analyze_path(
    path: Path,
    *,
    source: dict[str, object],
    workdir: Path,
    vt_api_key: str | None,
    dynamic_enabled: bool = False,
    tart_base_vm: str | None = None,
) -> dict[str, object]:
    emit(f"开始分析 {path.name}", "info", "phase")
    ctx = AnalysisContext()
    ctx.checks_run.add("file")
    emit("计算 SHA-256 和文件大小", "info", "step")
    sha256 = hash_path(path)
    ctx.metadata.update(
        {
            "filename": path.name,
            "size": path_size(path),
            "sha256": sha256,
            "analyzedAt": datetime.now(UTC).isoformat(),
            "inputType": classify(path),
        }
    )
    ctx.add("文件", "info", "已固定分析对象", "报告与该 SHA-256 对应。", sha256)
    emit(f"SHA-256: {sha256}", "success", "result")
    emit("检查下载来源与公开项目信誉", "info", "phase")
    inspect_source_reputation(source, ctx)
    inspect_product_reputation(source, ctx)

    emit(f"识别安装包类型：{classify(path).upper()}", "info", "phase")
    roots, cleanup = prepare_roots(path, workdir, ctx)
    try:
        emit("分析应用结构、签名、权限和安装影响", "info", "phase")
        inspect_roots(roots, ctx)
        emit("运行本地恶意软件检查", "info", "phase")
        inspect_local_av(path, roots, ctx)
        emit("查询 VirusTotal 多引擎信誉", "info", "phase")
        inspect_virustotal(sha256, vt_api_key, ctx)
        if dynamic_enabled:
            emit("启动 Tart 一次性虚拟机动态观察", "info", "phase")
            inspect_tart_dynamic(
                path,
                workdir,
                ctx,
                base_vm=tart_base_vm,
            )
        else:
            ctx.control(
                "dynamic_analysis",
                "not_run",
                "本次未启用 Tart 动态分析。",
            )
            ctx.control(
                "network_behavior",
                "not_run",
                "本次未启用运行时网络与文件行为观察。",
            )
    finally:
        emit("清理挂载点和临时分析数据", "info", "phase")
        cleanup()
    report = ctx.to_report(source)
    emit(
        f"分析完成：风险 {report['summary']['score']}/100，覆盖 "
        f"{report['coverage']['assessed']}/{report['coverage']['total']} 项",
        "success",
        "complete",
    )
    return report


def hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_dir():
        for item in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(str(item.relative_to(path)).encode())
            with item.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
    else:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def classify(path: Path) -> str:
    suffix = path.suffix.lower()
    if path.is_dir() and suffix == ".app":
        return "app"
    return {".dmg": "dmg", ".pkg": "pkg", ".zip": "zip"}.get(suffix, "file")


def prepare_roots(path: Path, workdir: Path, ctx: AnalysisContext):
    kind = classify(path)
    if kind == "app":
        return [path], lambda: None
    if kind == "dmg":
        return mount_dmg(path, ctx)
    if kind == "pkg":
        expanded = workdir / "expanded-pkg"
        result = run(["/usr/sbin/pkgutil", "--expand-full", str(path), str(expanded)], timeout=180)
        if result.returncode != 0:
            result = run(["/usr/sbin/pkgutil", "--expand", str(path), str(expanded)], timeout=180)
        ctx.checks_run.add("package")
        if result.returncode != 0:
            ctx.add("安装包", "high", "无法展开 PKG", "无法检查其安装内容和脚本。", result.output, 12, "scripts")
            return [path], lambda: None
        inspect_pkg_signature(path, ctx)
        return [expanded], lambda: None
    if kind == "zip":
        expanded = workdir / "expanded-zip"
        expanded.mkdir()
        result = run(["/usr/bin/ditto", "-x", "-k", str(path), str(expanded)], timeout=180)
        ctx.checks_run.add("package")
        if result.returncode != 0:
            ctx.add("安装包", "high", "无法展开 ZIP", "无法检查压缩包内容。", result.output, 12, "scripts")
            return [path], lambda: None
        return [expanded], lambda: None
    ctx.add("文件", "medium", "文件类型支持有限", "当前版本主要分析 APP、DMG、PKG 和 ZIP。", path.name, 5)
    return [path], lambda: None


def mount_dmg(path: Path, ctx: AnalysisContext):
    result = run(
        ["/usr/bin/hdiutil", "attach", "-plist", "-readonly", "-nobrowse", "-noautoopen", str(path)],
        timeout=180,
    )
    ctx.checks_run.add("package")
    if result.returncode != 0:
        ctx.add("磁盘映像", "high", "无法只读挂载 DMG", "无法检查映像中的应用。", result.output, 12, "signature")
        return [path], lambda: None
    try:
        payload = plistlib.loads(result.stdout.encode())
        mounts = [
            Path(entity["mount-point"])
            for entity in payload.get("system-entities", [])
            if entity.get("mount-point")
        ]
    except Exception:
        mounts = []
    if not mounts:
        ctx.add("磁盘映像", "high", "DMG 未提供挂载点", "无法检查映像内容。", result.output, 12, "signature")
        return [path], lambda: None

    def cleanup() -> None:
        for mount in reversed(mounts):
            run(["/usr/bin/hdiutil", "detach", str(mount), "-force"], timeout=60)

    return mounts, cleanup


def inspect_roots(roots: list[Path], ctx: AnalysisContext) -> None:
    emit("查找 .app 和嵌套 .pkg", "info", "step")
    apps: list[Path] = []
    pkg_files: list[Path] = []
    for root in roots:
        if root.is_dir() and root.suffix.lower() == ".app":
            apps.append(root)
        elif root.is_dir():
            apps.extend(find_bundles(root, ".app"))
            pkg_files.extend(find_bundles(root, ".pkg"))
    apps = unique_outermost(apps)
    emit(f"发现 {len(apps)} 个应用包、{len(pkg_files)} 个嵌套安装包", "info", "result")
    ctx.metadata["applications"] = [p.name for p in apps[:30]]
    if len(apps) > 30:
        ctx.add("安装内容", "medium", "应用组件数量很多", f"发现 {len(apps)} 个应用包。", points=5)
    for app in apps[:30]:
        emit(f"检查应用：{app.name}", "info", "step")
        inspect_app(app, ctx)
    for pkg in pkg_files[:20]:
        inspect_pkg_signature(pkg, ctx)
    emit("扫描持久化目录和高权限文件", "info", "step")
    inspect_filesystem(roots, ctx)
    emit("扫描安装脚本中的危险命令", "info", "step")
    inspect_scripts(roots, ctx)
    emit("评估敏感数据采集、存储、传输和遥测组件", "info", "step")
    inspect_data_security(roots, ctx)
    emit("盘点 Framework、动态库、运行时和更新框架", "info", "step")
    inspect_supply_chain(roots, ctx)
    emit("抽样分析 Mach-O 架构、加固与危险特征", "info", "step")
    inspect_static_binaries(roots, ctx)
    ctx.control(
        "vulnerabilities",
        "not_run",
        "已盘点可识别组件，但尚未接入可靠的版本识别和 CVE 匹配。",
    )
    if not apps and not pkg_files:
        ctx.add("安装内容", "medium", "未发现标准 macOS 应用", "输入中没有找到 .app 或嵌套 .pkg。", points=5)


def find_bundles(root: Path, suffix: str) -> list[Path]:
    matches: list[Path] = []
    for current, dirs, _ in os.walk(root):
        base = Path(current)
        for name in list(dirs):
            candidate = base / name
            if name.lower().endswith(suffix):
                matches.append(candidate)
                if suffix == ".app":
                    dirs.remove(name)
    return matches


def unique_outermost(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    for path in sorted(set(paths), key=lambda p: len(p.parts)):
        if not any(parent in path.parents for parent in result):
            result.append(path)
    return result


def inspect_app(app: Path, ctx: AnalysisContext) -> None:
    verify = run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app)])
    details = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(app)])
    detail_text = details.output
    authority = re.findall(r"^Authority=(.+)$", detail_text, re.M)
    team_id = match_value(detail_text, "TeamIdentifier")
    identifier = match_value(detail_text, "Identifier")
    if verify.returncode == 0:
        ctx.control("signature", "pass", "代码签名完整，未发现签名后篡改。")
        ctx.add(
            "签名",
            "info",
            f"{app.name} 签名完整",
            "代码签名通过严格校验，未发现签名后篡改。",
            "\n".join(authority + ([f"Team ID: {team_id}"] if team_id else [])),
            control_id="signature",
        )
    else:
        severity = "critical" if "invalid" in verify.output.lower() else "high"
        ctx.control("signature", "risk", "代码签名校验失败。", verify.output[-1500:])
        ctx.add("签名", severity, f"{app.name} 签名校验失败", "应用完整性或签名存在问题。", verify.output, 30 if severity == "critical" else 15, "signature")
    if "Signature=adhoc" in detail_text or not authority:
        ctx.control("publisher_identity", "risk", "没有可验证的 Developer ID 发布者。", detail_text[-1500:])
        ctx.add("签名", "high", f"{app.name} 没有可验证的 Developer ID", "无法确认公开发行者身份。", detail_text[-1500:], 12, "publisher_identity")
    else:
        publisher = authority[0]
        ctx.control(
            "publisher_identity",
            "pass",
            f"发布者身份可由 Apple Developer ID 验证：{publisher}",
            f"Team ID: {team_id or '未提供'}",
        )
    if team_id:
        ctx.metadata.setdefault("teamIds", [])
        if team_id not in ctx.metadata["teamIds"]:
            ctx.metadata["teamIds"].append(team_id)
    if identifier:
        ctx.metadata.setdefault("bundleIds", [])
        if identifier not in ctx.metadata["bundleIds"]:
            ctx.metadata["bundleIds"].append(identifier)

    gatekeeper = run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(app)])
    if gatekeeper.returncode == 0:
        ctx.control("gatekeeper", "pass", "通过 Apple Gatekeeper 评估。", gatekeeper.output)
        ctx.add("公证与 Gatekeeper", "info", f"{app.name} 通过 Gatekeeper", "系统允许在默认安全策略下运行。", gatekeeper.output, control_id="gatekeeper")
    else:
        inconclusive = any(
            marker in gatekeeper.output.lower()
            for marker in ("format unrecognized", "invalid, or unsuitable", "no usable signature")
        )
        if inconclusive and verify.returncode == 0:
            ctx.control("gatekeeper", "unknown", "Gatekeeper 对当前挂载位置或包格式无法给出有效结论。", gatekeeper.output)
            ctx.add("公证与 Gatekeeper", "medium", f"{app.name} 的 Gatekeeper 结果不确定", "签名完整，但 Gatekeeper 返回格式不适合评估；这不等同于公证失败。", gatekeeper.output, 4, "gatekeeper")
        else:
            ctx.control("gatekeeper", "risk", "未通过 Apple Gatekeeper 评估。", gatekeeper.output)
            ctx.add("公证与 Gatekeeper", "high", f"{app.name} 未通过 Gatekeeper", "可能未公证、未签名，或被系统策略拒绝。", gatekeeper.output, 12, "gatekeeper")

    entitlements = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(app)])
    inspect_entitlements(entitlements, app, ctx)
    inspect_info_plist(app, ctx)


def inspect_entitlements(result: CommandResult, app: Path, ctx: AnalysisContext) -> None:
    text = result.stdout or result.stderr
    start = text.find("<?xml")
    if start < 0:
        start = text.find("<plist")
    if start < 0:
        ctx.control("entitlements", "unknown", "没有提取到 Entitlements。")
        return
    end = text.find("</plist>", start)
    if end >= 0:
        text = text[: end + len("</plist>")]
    try:
        data = plistlib.loads(text[start:].encode())
    except Exception:
        ctx.control("entitlements", "unknown", "Entitlements 存在但无法解析。")
        return
    ctx.metadata.setdefault("entitlements", {})[app.name] = sorted(data)
    inspect_file_access_entitlements(data, app, ctx)
    sandboxed = data.get("com.apple.security.app-sandbox") is True
    sensitive = [
        key
        for key in ENTITLEMENT_RULES
        if key != "com.apple.security.app-sandbox" and data.get(key)
    ]
    ctx.control(
        "entitlements",
        "review" if sensitive else "pass",
        f"发现 {len(sensitive)} 项需要关注的敏感能力。" if sensitive else "未发现已知高影响 Entitlements。",
        "\n".join(sensitive),
    )
    if not sandboxed:
        ctx.add("权限能力", "low", f"{app.name} 未启用 App Sandbox", "应用不受 App Sandbox 的额外文件和资源访问限制。", points=3, control_id="entitlements")
    for key, (title, severity, points) in ENTITLEMENT_RULES.items():
        if data.get(key):
            ctx.add("权限能力", severity, title, f"{app.name} 声明了 {key}。", str(data.get(key)), points, "entitlements")


def inspect_file_access_entitlements(
    data: dict[str, object],
    app: Path,
    ctx: AnalysisContext,
) -> None:
    declared: list[str] = []
    write_access = False
    broad_access = False
    for key, (description, access_type) in FILE_ACCESS_ENTITLEMENTS.items():
        if data.get(key):
            declared.append(f"{description}（{key}）")
            write_access = write_access or access_type == "write"
    for key, description in FILE_EXCEPTION_ENTITLEMENTS.items():
        value = data.get(key)
        if value:
            declared.append(f"{description}：{value}")
            write_access = write_access or "read-write" in key
            broad_access = True
    bookmark_keys = [
        key
        for key in (
            "com.apple.security.files.bookmarks.app-scope",
            "com.apple.security.files.bookmarks.document-scope",
        )
        if data.get(key)
    ]
    if bookmark_keys:
        declared.append(
            "可保存安全作用域书签，以便后续再次访问用户授权过的文件或文件夹："
            + "、".join(bookmark_keys)
        )

    if declared:
        ctx.control(
            "file_access",
            "review" if broad_access else "observe",
            f"{app.name} 明确声明了 {len(declared)} 项文件访问能力。",
            "\n".join(declared),
        )
        ctx.add(
            "文件访问",
            "medium" if broad_access else "info",
            "声明文件或目录访问能力",
            "用户选择型权限仍要求用户主动选择目标；只有绝对路径或 Home 相对路径沙箱例外需要人工核对。",
            "\n".join(declared),
            5 if broad_access else 0,
            "file_access",
        )
    else:
        ctx.control(
            "file_access",
            "unknown",
            "未发现沙箱文件访问 Entitlements；未启用沙箱的应用仍可能通过运行时授权访问文件。",
        )


def inspect_info_plist(app: Path, ctx: AnalysisContext) -> None:
    plist_path = app / "Contents" / "Info.plist"
    if not plist_path.exists():
        ctx.control("privacy", "unknown", "缺少 Info.plist，无法检查隐私权限声明。")
        ctx.add("应用结构", "medium", f"{app.name} 缺少 Info.plist", "不是完整的标准应用包。", points=5)
        return
    try:
        with plist_path.open("rb") as handle:
            data = plistlib.load(handle)
    except Exception as exc:
        ctx.control("privacy", "unknown", "Info.plist 无法解析。", str(exc))
        ctx.add("应用结构", "medium", f"{app.name} 的 Info.plist 无法解析", str(exc), points=5)
        return
    version = data.get("CFBundleShortVersionString") or data.get("CFBundleVersion")
    if version:
        ctx.metadata.setdefault("versions", {})[app.name] = str(version)
    privacy_found = []
    folder_declarations = []
    sensitive_declarations = []
    for key, (label, severity, points) in PRIVACY_KEYS.items():
        if key in data:
            privacy_found.append(label)
            if key not in {
                "NSDesktopFolderUsageDescription",
                "NSDocumentsFolderUsageDescription",
                "NSDownloadsFolderUsageDescription",
            }:
                sensitive_declarations.append(f"{label}：{data[key]}")
            if key in {
                "NSDesktopFolderUsageDescription",
                "NSDocumentsFolderUsageDescription",
                "NSDownloadsFolderUsageDescription",
            }:
                folder_declarations.append(f"{label}：{data[key]}")
            ctx.add(
                "隐私权限",
                severity,
                f"可能请求{label}权限",
                f"{app.name} 声明了系统权限用途。实际授权仍需用户确认。",
                str(data[key]),
                points,
                "privacy",
            )
    if folder_declarations:
        ctx.control(
            "file_access",
            "review",
            f"Info.plist 声明可能访问桌面、文稿或下载目录，共 {len(folder_declarations)} 项。",
            "\n".join(folder_declarations),
        )
    if sensitive_declarations:
        ctx.control(
            "sensitive_data",
            "review",
            f"Info.plist 明确声明可能采集 {len(sensitive_declarations)} 类敏感数据。",
            "\n".join(sensitive_declarations),
        )
        ctx.add(
            "数据安全",
            "medium",
            "声明敏感数据访问用途",
            "系统仍要求用户授权，但企业应确认采集目的、最小必要性和保存方式。",
            "\n".join(sensitive_declarations),
            5,
            "sensitive_data",
        )
    ats = data.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        arbitrary = bool(
            ats.get("NSAllowsArbitraryLoads")
            or ats.get("NSAllowsArbitraryLoadsInWebContent")
        )
        if arbitrary:
            ctx.control(
                "privacy_manifest",
                "risk",
                "App Transport Security 允许任意或 Web 内容非安全传输。",
                plistlib.dumps(ats).decode(errors="replace"),
            )
            ctx.add(
                "数据传输",
                "high",
                "允许放宽 HTTPS 传输保护",
                "部分网络请求可能不受默认 ATS 安全要求约束。",
                str(ats),
                10,
                "privacy_manifest",
            )
        else:
            ctx.control(
                "privacy_manifest",
                "pass",
                "未发现全局放宽 App Transport Security 的配置。",
                str(ats),
            )
    ctx.control(
        "privacy",
        "review" if privacy_found else "pass",
        f"声明了 {len(privacy_found)} 类隐私权限：{'、'.join(privacy_found)}。" if privacy_found else "未发现 Info.plist 隐私权限用途声明。",
    )
    if data.get("LSUIElement"):
        ctx.add("运行方式", "low", "包含后台菜单栏/无 Dock 应用", f"{app.name} 可不显示普通 Dock 图标运行。", points=2, control_id="persistence")


def inspect_pkg_signature(pkg: Path, ctx: AnalysisContext) -> None:
    result = run(["/usr/sbin/pkgutil", "--check-signature", str(pkg)])
    if result.returncode == 0 and "Status: signed by a certificate trusted" in result.output:
        ctx.control("signature", "pass", "PKG 签名链被系统信任。", result.output[-1800:])
        ctx.control("publisher_identity", "pass", "安装包发布者身份可由签名验证。", result.output[-1800:])
        ctx.add("签名", "info", f"{pkg.name} 安装包签名可信", "PKG 签名链被系统信任。", result.output[-1800:], control_id="signature")
    elif result.returncode == 0 and "no signature" not in result.output.lower():
        ctx.control("signature", "review", "安装包存在签名，但信任状态需要复核。", result.output[-1800:])
        ctx.add("签名", "medium", f"{pkg.name} 安装包签名需要复核", "签名存在，但信任状态不明确。", result.output[-1800:], 7, "signature")
    else:
        ctx.control("signature", "risk", "安装包没有可信签名。", result.output[-1800:])
        ctx.control("publisher_identity", "risk", "无法通过 PKG 签名确认发布者身份。", result.output[-1800:])
        ctx.add("签名", "high", f"{pkg.name} 安装包未可信签名", "无法可靠确认安装包发布者。", result.output[-1800:], 12, "signature")


def inspect_filesystem(roots: list[Path], ctx: AnalysisContext) -> None:
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for item in root.rglob("*"):
            name = item.name
            if name in PERSISTENCE_NAMES and name not in seen:
                title, severity, points = PERSISTENCE_NAMES[name]
                ctx.add("系统影响", severity, title, "安装内容中发现可能常驻或扩展系统能力的组件。", str(item), points, "persistence")
                seen.add(name)
            try:
                mode = item.lstat().st_mode
            except OSError:
                continue
            if mode & stat.S_ISUID:
                ctx.add("系统影响", "high", "包含 SUID 文件", "该文件可能以文件所有者权限运行。", str(item), 12, "persistence")
                seen.add("SUID")
    ctx.control(
        "persistence",
        "risk"
        if any(
            finding.control_id == "persistence"
            and finding.severity in {"high", "critical"}
            for finding in ctx.findings
        )
        else "review"
        if seen
        else "pass",
        f"发现 {len(seen)} 类常驻、扩展或高权限组件。" if seen else "未发现常见持久化目录或 SUID 文件。",
        "、".join(sorted(seen)),
    )


def inspect_scripts(roots: list[Path], ctx: AnalysisContext) -> None:
    files_seen = 0
    matches_seen: set[tuple[str, str]] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if files_seen >= 5000:
                return
            if not path.is_file():
                continue
            files_seen += 1
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:4096]:
                continue
            text = raw.decode("utf-8", errors="ignore")
            for pattern, title, severity, points in SCRIPT_RULES:
                match = pattern.search(text)
                key = (str(path), title)
                if match and key not in matches_seen:
                    line = text.count("\n", 0, match.start()) + 1
                    evidence = f"{path}，第 {line} 行附近：{match.group(0)[:300]}"
                    ctx.add("安装脚本", severity, title, "静态检查发现相关命令；需人工确认上下文和用途。", evidence, points, "scripts")
                    matches_seen.add(key)
    severe = any(f.severity in {"high", "critical"} and f.category == "安装脚本" for f in ctx.findings)
    ctx.control(
        "scripts",
        "risk" if severe else "observe" if matches_seen else "pass",
        f"安装脚本命中 {len(matches_seen)} 条关注规则。" if matches_seen else "未发现已知危险安装脚本模式。",
    )


def inspect_data_security(roots: list[Path], ctx: AnalysisContext) -> None:
    sensitive_hits: set[str] = set()
    transmission_hits: set[str] = set()
    storage_hits: set[str] = set()
    encryption_hits: set[str] = set()
    telemetry_hits: set[str] = set()
    manifests: list[str] = []
    collected_types: set[str] = set()
    tracking_enabled = False
    scanned_files = 0

    for root in roots:
        if not root.is_dir():
            continue
        for item in root.rglob("*"):
            if scanned_files >= 25000:
                break
            name = item.name
            for marker, product in TELEMETRY_MARKERS.items():
                if marker.lower() in name.lower():
                    telemetry_hits.add(f"{product}：{item}")
            if not item.is_file():
                continue
            scanned_files += 1
            if name == "PrivacyInfo.xcprivacy":
                manifests.append(str(item))
                try:
                    with item.open("rb") as handle:
                        privacy_data = plistlib.load(handle)
                    tracking_enabled = tracking_enabled or bool(
                        privacy_data.get("NSPrivacyTracking")
                    )
                    for entry in privacy_data.get("NSPrivacyCollectedDataTypes", []):
                        if not isinstance(entry, dict):
                            continue
                        data_type = str(
                            entry.get("NSPrivacyCollectedDataType", "未知数据类型")
                        )
                        linked = bool(
                            entry.get("NSPrivacyCollectedDataTypeLinked")
                        )
                        tracking = bool(
                            entry.get("NSPrivacyCollectedDataTypeTracking")
                        )
                        purposes = entry.get(
                            "NSPrivacyCollectedDataTypePurposes", []
                        )
                        collected_types.add(
                            f"{data_type}；关联身份={'是' if linked else '否'}；"
                            f"用于追踪={'是' if tracking else '否'}；用途={purposes}"
                        )
                except Exception as exc:
                    manifests.append(f"{item}（解析失败：{exc}）")

            try:
                size = item.stat().st_size
                if size > 20 * 1024 * 1024:
                    continue
                with item.open("rb") as handle:
                    sample = handle.read(20 * 1024 * 1024)
            except OSError:
                continue
            for marker, description in SENSITIVE_DATA_MARKERS.items():
                if marker in sample:
                    sensitive_hits.add(f"{item.name}: {description}")
            for marker, description in DATA_TRANSMISSION_MARKERS.items():
                if marker.lower() in sample.lower():
                    transmission_hits.add(f"{item.name}: {description}")
            for marker, description in LOCAL_STORAGE_MARKERS.items():
                if marker.lower() in sample.lower():
                    storage_hits.add(f"{item.name}: {description}")
            for marker, description in ENCRYPTION_MARKERS.items():
                if marker.lower() in sample.lower():
                    encryption_hits.add(f"{item.name}: {description}")
            for marker, product in TELEMETRY_MARKERS.items():
                if marker.lower().encode() in sample.lower():
                    telemetry_hits.add(f"{item.name}: {product}")

    ctx.metadata["dataSecurity"] = {
        "privacyManifests": manifests,
        "collectedDataTypes": sorted(collected_types),
        "trackingDeclared": tracking_enabled,
        "sensitiveApiHints": sorted(sensitive_hits),
        "transmissionHints": sorted(transmission_hits),
        "storageHints": sorted(storage_hits),
        "encryptionHints": sorted(encryption_hits),
        "telemetrySdks": sorted(telemetry_hits),
    }

    if sensitive_hits:
        evidence = static_hint_evidence(sensitive_hits)
        ctx.control(
            "sensitive_data",
            "observe",
            f"发现 {len(sensitive_hits)} 项敏感数据采集 API 线索。",
            evidence,
        )
        ctx.add(
            "数据安全",
            "low",
            "包含敏感数据采集能力线索",
            "这些 API 可能服务于正常功能，是否实际采集需要动态分析和隐私政策确认。",
            evidence,
            min(3, len(sensitive_hits)),
            "sensitive_data",
        )
    elif "sensitive_data" not in ctx.controls:
        ctx.control(
            "sensitive_data",
            "pass",
            "未发现已知敏感数据采集声明或 API 线索。",
        )

    if transmission_hits:
        evidence = static_hint_evidence(transmission_hits)
        ctx.control(
            "data_transmission",
            "observe",
            f"发现 {len(transmission_hits)} 项联网、上传或云同步能力线索。",
            evidence,
        )
        ctx.add(
            "数据安全",
            "low",
            "包含数据传输或云同步能力",
            "联网能力不代表上传敏感数据；运行时需要核实目标域名、数据内容和加密方式。",
            evidence,
            1,
            "data_transmission",
        )
    else:
        ctx.control(
            "data_transmission",
            "unknown",
            "未发现内置传输线索，但静态分析无法证明应用不会联网或上传数据。",
        )

    if storage_hits:
        storage_evidence = static_hint_evidence(storage_hits)
        encryption_evidence = static_hint_evidence(encryption_hits)
        if encryption_hits:
            ctx.control(
                "local_data_protection",
                "observe",
                "发现本地数据存储，同时发现加密或 Keychain 能力；无法确认所有数据均受保护。",
                f"存储线索：\n{storage_evidence}\n\n保护线索：\n{encryption_evidence}",
            )
        else:
            ctx.control(
                "local_data_protection",
                "review",
                "发现本地数据存储线索，但未发现明确加密组件。",
                storage_evidence,
            )
            ctx.add(
                "数据安全",
                "medium",
                "本地存储保护需要确认",
                "未发现加密线索不等于明文存储，但企业应确认缓存、日志和数据库是否加密。",
                storage_evidence,
                5,
                "local_data_protection",
            )
    elif encryption_hits:
        ctx.control(
            "local_data_protection",
            "pass",
            "发现 Keychain 或加密组件，未发现常见本地数据库线索。",
            static_hint_evidence(encryption_hits),
        )
    else:
        ctx.control(
            "local_data_protection",
            "unknown",
            "未识别到明确的本地存储或加密实现，无法判断数据落盘保护情况。",
        )

    if telemetry_hits:
        evidence = "\n".join(sorted(telemetry_hits)[:80])
        ctx.control(
            "telemetry_tracking",
            "review",
            f"识别到 {len(telemetry_hits)} 项遥测、分析或崩溃上报 SDK 线索。",
            evidence,
        )
        ctx.add(
            "数据安全",
            "medium",
            "包含遥测或崩溃上报组件",
            "需要确认默认是否启用、采集字段、是否包含文件名或用户标识，以及能否由企业关闭。",
            evidence,
            5,
            "telemetry_tracking",
        )
    else:
        ctx.control(
            "telemetry_tracking",
            "pass",
            "未识别到常见遥测、分析或崩溃上报 SDK。",
        )

    if manifests:
        manifest_evidence = (
            "清单文件：\n"
            + "\n".join(manifests)
            + (
                "\n\n声明收集的数据：\n" + "\n".join(sorted(collected_types))
                if collected_types
                else "\n\n未声明收集数据类型。"
            )
        )
        status = "review" if tracking_enabled or collected_types else "pass"
        ctx.control(
            "privacy_manifest",
            status,
            f"发现 {len(manifests)} 个 Privacy Manifest；"
            f"声明 {len(collected_types)} 类数据；追踪声明={'是' if tracking_enabled else '否'}。",
            manifest_evidence,
        )
        if tracking_enabled or collected_types:
            ctx.add(
                "隐私治理",
                "medium" if tracking_enabled else "low",
                "Privacy Manifest 声明数据收集或追踪",
                "这是开发者或第三方 SDK 的正式声明，应与企业可接受用途和隐私政策核对。",
                manifest_evidence,
                7 if tracking_enabled else 3,
                "privacy_manifest",
            )
    elif "privacy_manifest" not in ctx.controls:
        ctx.control(
            "privacy_manifest",
            "unknown",
            "未发现 PrivacyInfo.xcprivacy，也未发现明确 ATS 结论。",
        )


def static_hint_evidence(values: set[str]) -> str:
    return (
        "以下为静态代码或组件线索，不代表运行时一定执行：\n"
        + "\n".join(sorted(values)[:80])
    )


def inspect_tart_dynamic(
    path: Path,
    workdir: Path,
    ctx: AnalysisContext,
    *,
    base_vm: str | None = None,
) -> None:
    observation = observe_with_tart(
        path,
        workdir,
        base_vm=base_vm,
        duration=int(os.getenv("TART_OBSERVATION_SECONDS", "20")),
    )
    ctx.metadata["dynamicObservation"] = observation.as_metadata()
    behavior = observation.behavior
    processes = behavior.get("processes", []) if isinstance(behavior, dict) else []
    connections = behavior.get("connections", []) if isinstance(behavior, dict) else []
    dns_queries = behavior.get("dnsQueries", []) if isinstance(behavior, dict) else []
    file_activities = (
        behavior.get("fileActivities", []) if isinstance(behavior, dict) else []
    )
    evidence_parts = [
        observation.summary,
        f"一次性 VM：{observation.vm_name or '未创建'}",
        f"应用进程：{observation.executable or '未识别'}",
        f"Bundle ID：{observation.bundle_id or '未识别'}",
    ]
    if observation.collectors:
        evidence_parts.append("事件采集器：\n" + "\n".join(observation.collectors))
    process_tree = str(behavior.get("processTree", "")).strip()
    if process_tree:
        evidence_parts.append("进程树：\n" + process_tree)
    if connections:
        evidence_parts.append(
            "去重后的远程连接：\n"
            + "\n".join(_format_connection(item) for item in connections[:80])
        )
    if dns_queries:
        evidence_parts.append(
            "DNS 查询：\n"
            + "\n".join(_format_dns_query(item) for item in dns_queries[:80])
        )
    if file_activities:
        evidence_parts.append(
            "去重后的文件操作：\n"
            + "\n".join(_format_file_activity(item) for item in file_activities[:100])
        )
    if observation.logs:
        evidence_parts.append("相关统一日志：\n" + "\n".join(observation.logs))
    evidence = "\n\n".join(evidence_parts)

    if observation.status == "not_run":
        ctx.control("dynamic_analysis", "not_run", observation.summary, evidence)
        ctx.control("network_behavior", "not_run", observation.summary, evidence)
        return
    if observation.status == "failed":
        ctx.control("dynamic_analysis", "review", observation.summary, evidence)
        ctx.control("network_behavior", "unknown", "动态网络观察失败。", evidence)
        return

    ctx.control(
        "dynamic_analysis",
        "observe",
        f"已在 Tart 一次性 macOS VM 中观察到 {len(processes)} 个目标进程族进程。",
        evidence,
    )
    if connections or dns_queries or file_activities:
        summary_parts = []
        if connections:
            summary_parts.append(f"{len(connections)} 条去重远程连接")
        if dns_queries:
            summary_parts.append(f"{len(dns_queries)} 个 DNS 域名")
        if file_activities:
            summary_parts.append(f"{len(file_activities)} 个去重文件操作")
        ctx.control(
            "network_behavior",
            "observe",
            "观察到" + "、".join(summary_parts) + "。",
            "\n\n".join(
                part
                for part in (
                    "\n".join(_format_connection(item) for item in connections),
                    "\n".join(_format_dns_query(item) for item in dns_queries),
                    "\n".join(_format_file_activity(item) for item in file_activities),
                )
                if part
            ),
        )
    else:
        ctx.control(
            "network_behavior",
            "pass",
            "在限时观察中未记录到目标应用的远程连接或文件变更。",
            evidence,
        )


def _format_connection(item: object) -> str:
    if not isinstance(item, dict):
        return str(item)
    states = ",".join(str(value) for value in item.get("states", [])) or "observed"
    domains = ",".join(str(value) for value in item.get("domains", []))
    target = f"{item.get('remoteAddress', '?')}:{item.get('remotePort', '?')}"
    if domains:
        target = f"{domains} -> {target}"
    return (
        f"{item.get('protocol', 'IP')} {target} "
        f"[{item.get('process', '未知进程')} pid={item.get('pid', 0)}; "
        f"{states}; {item.get('samples', 1)} 次]"
    )


def _format_dns_query(item: object) -> str:
    if not isinstance(item, dict):
        return str(item)
    types = ",".join(str(value) for value in item.get("types", [])) or "DNS"
    addresses = ",".join(str(value) for value in item.get("addresses", []))
    return (
        f"{item.get('domain', '?')} [{types}; {item.get('count', 1)} 次"
        + (f"; {addresses}" if addresses else "")
        + "]"
    )


def _format_file_activity(item: object) -> str:
    if not isinstance(item, dict):
        return str(item)
    return (
        f"{str(item.get('action', 'modify')).upper()} {item.get('path', '?')} "
        f"[{item.get('process', '目标应用')} pid={item.get('pid', 0)}; "
        f"{item.get('count', 1)} 次]"
    )


def inspect_source_reputation(source: dict[str, object], ctx: AnalysisContext) -> None:
    homepage = str(source.get("homepage", "")).strip()
    final_url = str(source.get("finalUrl", "")).strip()
    original_url = str(source.get("originalUrl", "")).strip()
    if not final_url and not homepage:
        ctx.control(
            "source_reputation",
            "unknown",
            "仅上传了文件，未提供官网，无法验证下载来源与厂商的一致性。",
        )
        return

    evidence = []
    status = "pass"
    summary = (
        "下载来源使用 HTTPS，且可进行域名核对。"
        if final_url
        else "已提供 HTTPS 产品主页，可用于发布者核对；上传文件本身的下载链路未知。"
    )
    if final_url:
        parsed = urllib.parse.urlparse(final_url)
        evidence.append(f"最终下载域名：{parsed.hostname or '未知'}")
        if parsed.scheme != "https":
            status = "risk"
            summary = "最终下载地址没有使用 HTTPS。"
        redirects = source.get("redirects") or []
        evidence.append(f"重定向次数：{len(redirects)}")
    if original_url:
        evidence.append(f"原始地址：{original_url}")
    if homepage:
        home = urllib.parse.urlparse(homepage)
        evidence.append(f"产品主页域名：{home.hostname or '未知'}")
        if home.scheme != "https":
            status = "review" if status == "pass" else status
            summary = "产品主页没有使用 HTTPS，需人工确认来源。"
        if final_url:
            download_host = urllib.parse.urlparse(final_url).hostname or ""
            home_host = home.hostname or ""
            if not same_organization_domain(download_host, home_host):
                status = "review" if status != "risk" else status
                summary = "下载域名与提供的产品主页域名不同，可能是 CDN，也可能需要核实。"
    ctx.control("source_reputation", status, summary, "\n".join(evidence))


def same_organization_domain(first: str, second: str) -> bool:
    def base(host: str) -> str:
        parts = host.lower().strip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    return bool(first and second and base(first) == base(second))


def inspect_product_reputation(source: dict[str, object], ctx: AnalysisContext) -> None:
    homepage = str(source.get("homepage", "")).strip()
    parsed = urllib.parse.urlparse(homepage)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        ctx.control(
            "product_reputation",
            "unknown",
            "未提供可自动核验的公开项目地址。普通官网暂不按“知名度”主观评分。",
        )
        return
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        ctx.control("product_reputation", "unknown", "GitHub 地址不是具体仓库页面。")
        return
    owner, repo = parts[0], parts[1].removesuffix(".git")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "CanUInstall/0.2",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read())
    except Exception as exc:
        ctx.control(
            "product_reputation",
            "unknown",
            "GitHub 公开仓库信息查询失败。",
            str(exc),
        )
        return

    stars = int(data.get("stargazers_count", 0))
    forks = int(data.get("forks_count", 0))
    archived = bool(data.get("archived"))
    license_name = (data.get("license") or {}).get("spdx_id") or "未识别"
    created = parse_github_time(data.get("created_at"))
    pushed = parse_github_time(data.get("pushed_at"))
    now = datetime.now(UTC)
    age_days = (now - created).days if created else None
    stale_days = (now - pushed).days if pushed else None
    evidence = (
        f"仓库：{data.get('full_name', f'{owner}/{repo}')}\n"
        f"Stars：{stars}；Forks：{forks}\n"
        f"创建时间：{data.get('created_at', '未知')}\n"
        f"最近推送：{data.get('pushed_at', '未知')}\n"
        f"许可证：{license_name}；已归档：{'是' if archived else '否'}"
    )
    ctx.metadata["publicProject"] = {
        "provider": "GitHub",
        "repository": data.get("full_name"),
        "stars": stars,
        "forks": forks,
        "createdAt": data.get("created_at"),
        "pushedAt": data.get("pushed_at"),
        "archived": archived,
        "license": license_name,
    }
    if archived:
        ctx.control("product_reputation", "risk", "公开项目已归档，不再积极维护。", evidence)
        ctx.add("产品信誉", "medium", "公开项目已经归档", "停止维护会增加漏洞无法及时修复的风险。", evidence, 7, "product_reputation")
    elif stale_days is not None and stale_days > 730:
        ctx.control("product_reputation", "review", f"公开项目已约 {stale_days} 天没有代码推送。", evidence)
        ctx.add("产品信誉", "low", "公开项目长期未更新", "需要确认软件是否仍受支持以及安全更新渠道。", evidence, 3, "product_reputation")
    elif age_days is not None and age_days < 180 and stars < 10:
        ctx.control("product_reputation", "observe", "项目历史较短、公开采用信号有限；这不表示恶意。", evidence)
    else:
        ctx.control("product_reputation", "pass", "公开项目存在持续维护记录和可核验的社区信息。", evidence)


def parse_github_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def inspect_supply_chain(roots: list[Path], ctx: AnalysisContext) -> None:
    frameworks: list[str] = []
    dylibs: list[str] = []
    runtimes: set[str] = set()
    updates: set[str] = set()
    manifests: list[str] = []
    scanned = 0
    for root in roots:
        if not root.is_dir():
            continue
        for item in root.rglob("*"):
            if scanned >= 25000:
                break
            scanned += 1
            name = item.name
            if item.is_dir() and name.endswith(".framework") and len(frameworks) < 100:
                frameworks.append(name.removesuffix(".framework"))
            elif item.is_file() and name.endswith(".dylib") and len(dylibs) < 100:
                dylibs.append(name)
            if name in RUNTIME_MARKERS:
                runtimes.add(RUNTIME_MARKERS[name])
            if name in UPDATE_MARKERS:
                updates.add(UPDATE_MARKERS[name])
            if name in DEPENDENCY_FILES and len(manifests) < 30:
                manifests.append(str(item))

    ctx.metadata["supplyChain"] = {
        "frameworks": sorted(set(frameworks)),
        "dynamicLibraries": sorted(set(dylibs)),
        "runtimes": sorted(runtimes),
        "updateFrameworks": sorted(updates),
        "dependencyFiles": manifests,
    }
    component_count = len(set(frameworks)) + len(set(dylibs))
    ctx.control(
        "components",
        "pass",
        f"盘点到 {len(set(frameworks))} 个 Framework、{len(set(dylibs))} 个动态库。"
        if component_count
        else "未发现独立打包的第三方 Framework 或动态库。",
        "\n".join((frameworks + dylibs)[:80]),
    )
    ctx.control(
        "bundled_runtimes",
        "observe" if runtimes else "pass",
        f"识别到捆绑运行时：{'、'.join(sorted(runtimes))}。" if runtimes else "未识别到常见大型捆绑运行时。",
    )
    ctx.control(
        "dependency_manifests",
        "pass" if manifests else "unknown",
        f"发现 {len(manifests)} 个依赖清单或锁文件，可用于进一步生成 SBOM。"
        if manifests
        else "发行包中没有发现可直接读取的依赖锁文件；这不代表没有第三方依赖。",
        "\n".join(manifests),
    )
    ctx.control(
        "update_framework",
        "observe" if updates else "unknown",
        f"发现自动更新组件：{'、'.join(sorted(updates))}。需继续核实更新签名与下载地址。"
        if updates
        else "未识别到常见自动更新框架，可能使用自研更新机制或不提供自动更新。",
    )
    if runtimes:
        ctx.add(
            "供应链",
            "low",
            "包含大型第三方运行时",
            "捆绑运行时会扩大依赖和漏洞管理范围，但本身不表示恶意。",
            "、".join(sorted(runtimes)),
            2,
            "bundled_runtimes",
        )


def inspect_static_binaries(roots: list[Path], ctx: AnalysisContext) -> None:
    macho_files: list[Path] = []
    architectures: set[str] = set()
    rule_hits: list[str] = []
    reported_rules: set[str] = set()
    path_hints: set[str] = set()
    hardened = 0
    candidates = 0
    for root in roots:
        if not root.is_dir():
            continue
        for item in root.rglob("*"):
            if len(macho_files) >= 120:
                break
            if not item.is_file():
                continue
            try:
                with item.open("rb") as handle:
                    magic = handle.read(4)
            except OSError:
                continue
            if magic not in {
                b"\xcf\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe",
                b"\xbe\xba\xfe\xca",
                b"\xca\xfe\xba\xbf",
                b"\xbf\xba\xfe\xca",
            }:
                continue
            macho_files.append(item)
            info = run(["/usr/bin/file", str(item)], timeout=15)
            lower = info.output.lower()
            if "arm64" in lower:
                architectures.add("arm64")
            if "x86_64" in lower:
                architectures.add("x86_64")
            details = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(item)], timeout=15)
            candidates += 1
            if "runtime" in details.output.lower():
                hardened += 1
            try:
                with item.open("rb") as handle:
                    sample = handle.read(16 * 1024 * 1024)
            except OSError:
                continue
            for marker, title, severity, points in STATIC_BINARY_RULES:
                if marker in sample:
                    evidence = f"{item.name}: {marker.decode(errors='replace')}"
                    rule_hits.append(evidence)
                    if title not in reported_rules:
                        ctx.add(
                            "静态安全",
                            severity,
                            title,
                            "二进制包含相关 API 或字符串，需要结合软件用途人工判断。",
                            evidence,
                            points,
                            "static_indicators",
                        )
                        reported_rules.add(title)
            for marker, description in SENSITIVE_PATH_MARKERS.items():
                if marker in sample:
                    path_hints.add(f"{item.name}: {description}")

    ctx.metadata["binaries"] = {
        "machOCount": len(macho_files),
        "architectures": sorted(architectures),
        "hardenedRuntimeObserved": hardened,
        "sampledForHardening": candidates,
    }
    ctx.control(
        "static_indicators",
        "review" if rule_hits else "pass",
        f"静态特征命中 {len(rule_hits)} 项需要复核的能力。" if rule_hits else "在抽样 Mach-O 中未命中内置危险特征规则。",
        "\n".join(rule_hits[:50]),
    )
    if path_hints:
        existing = ctx.controls.get("file_access", {})
        existing_evidence = existing.get("evidence", "")
        hint_text = (
            "以下仅为二进制字符串线索，不能证明运行时一定访问：\n"
            + "\n".join(sorted(path_hints)[:50])
        )
        ctx.control(
            "file_access",
            "review",
            existing.get(
                "summary",
                f"发现 {len(path_hints)} 项敏感目录访问线索，需要运行时验证。",
            ),
            "\n\n".join(value for value in (existing_evidence, hint_text) if value),
        )
        ctx.add(
            "文件访问",
            "low",
            "发现敏感目录路径线索",
            "路径字符串可能来自正常功能、依赖库或错误信息，不能单独证明实际读取。",
            "\n".join(sorted(path_hints)[:50]),
            2,
            "file_access",
        )
    if not macho_files:
        ctx.control("binary_hardening", "unknown", "没有识别到 Mach-O 可执行文件。")
    else:
        hardening_status = "pass" if hardened == candidates else "review"
        ctx.control(
            "binary_hardening",
            hardening_status,
            f"识别到 {len(macho_files)} 个 Mach-O；架构：{'、'.join(sorted(architectures)) or '未知'}；"
            f"{hardened}/{candidates} 个抽样文件显示 Hardened Runtime 标记。",
        )


def inspect_local_av(path: Path, roots: list[Path], ctx: AnalysisContext) -> None:
    clamscan = shutil.which("clamscan")
    if not clamscan:
        ctx.control(
            "local_av",
            "not_run",
            "本机没有安装 ClamAV；当前仅运行内置静态规则。",
        )
        return
    targets = [path] if path.is_file() else roots
    outputs = []
    infected = False
    for target in targets[:5]:
        args = [clamscan, "--no-summary"]
        if target.is_dir():
            args.append("-r")
        result = run(args + [str(target)], timeout=300)
        outputs.append(result.output)
        infected = infected or result.returncode == 1
    if infected:
        ctx.control("local_av", "risk", "ClamAV 检测到恶意内容。", "\n".join(outputs)[-4000:])
        ctx.add("本地杀毒", "critical", "ClamAV 检测到恶意内容", "本地杀毒引擎返回感染结果。", "\n".join(outputs)[-4000:], 35, "local_av")
    else:
        ctx.control("local_av", "pass", "ClamAV 未检测到已知恶意内容。", "\n".join(outputs)[-2000:])


def inspect_virustotal(
    sha256: str,
    api_key: str | None,
    ctx: AnalysisContext,
    *,
    now: datetime | None = None,
) -> None:
    if not api_key:
        ctx.control("virustotal", "not_run", "未配置 VirusTotal API Key。")
        ctx.add("VirusTotal", "info", "未配置 VirusTotal", "设置 VIRUSTOTAL_API_KEY 后可查询多引擎结果。", control_id="virustotal")
        return
    lookup = virustotal.lookup(sha256, api_key)
    if lookup["status"] == 404:
        ctx.control(
            "virustotal",
            "observe",
            "VirusTotal 没有该 SHA-256 的公开记录，公开样本历史不足。",
        )
        ctx.metadata["virusTotal"] = {
            "found": False,
            "historyMaturity": "unseen",
        }
        ctx.add(
            "VirusTotal",
            "low",
            "VirusTotal 无公开样本记录",
            "这可能是新版本、小众软件或私有发行包，并不表示恶意；但缺少公开检测历史会降低结论置信度。",
            "仅按 SHA-256 查询，未上传文件。",
            2,
            "virustotal",
        )
        return
    if lookup["status"] not in {200, 201}:
        message = lookup["payload"].get("error", {}).get("message", "未知 API 错误")
        ctx.control("virustotal", "unknown", "VirusTotal 查询失败。", message)
        ctx.add("VirusTotal", "medium", "VirusTotal 查询失败", message, points=4, control_id="virustotal")
        return
    attrs = lookup["payload"].get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    history = assess_virustotal_history(attrs, now=now)
    ctx.metadata["virusTotal"] = {
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        **history,
    }
    evidence = virustotal_evidence(stats, history)
    if malicious >= 5:
        ctx.control("virustotal", "risk", f"{malicious} 个引擎判定恶意。", evidence)
        ctx.add("VirusTotal", "critical", f"{malicious} 个引擎判定恶意", "多引擎一致命中，建议直接拒绝。", evidence, 40, "virustotal")
    elif malicious >= 2:
        ctx.control("virustotal", "risk", f"{malicious} 个引擎判定恶意。", evidence)
        ctx.add("VirusTotal", "high", f"{malicious} 个引擎判定恶意", "需要安全人员核实检测名称和引擎可靠性。", evidence, 18, "virustotal")
    elif malicious == 1 or suspicious:
        ctx.control("virustotal", "review", "存在少量恶意或可疑命中。", evidence)
        ctx.add("VirusTotal", "medium", "VirusTotal 存在少量命中", "可能是误报，也可能是新威胁，不能自动放行。", evidence, 8, "virustotal")
    else:
        age_days = int(history["ageDays"])
        if age_days < 30:
            ctx.control(
                "virustotal",
                "observe",
                f"多引擎当前无恶意命中，但该哈希仅有 {age_days} 天公开历史。",
                evidence,
            )
            ctx.add(
                "VirusTotal",
                "low",
                "VirusTotal 样本历史很短",
                "当前未命中恶意，但样本首次出现不足 30 天，尚未形成充分的公开检测历史。",
                evidence,
                3,
                "virustotal",
            )
        elif age_days < 180:
            ctx.control(
                "virustotal",
                "observe",
                f"多引擎当前无恶意命中；该哈希公开历史约 {age_days} 天。",
                evidence,
            )
            ctx.add(
                "VirusTotal",
                "low",
                "VirusTotal 样本历史较短",
                "当前未命中恶意，但公开历史不足半年，作为轻微不确定性信号。",
                evidence,
                1,
                "virustotal",
            )
        elif age_days >= 730:
            ctx.control(
                "virustotal",
                "pass",
                f"该哈希已有约 {age_days // 365} 年公开历史，最新多引擎扫描仍无恶意或可疑命中。",
                evidence,
            )
            ctx.add(
                "VirusTotal",
                "info",
                "VirusTotal 样本历史成熟",
                "较长公开历史且最新扫描无恶意或可疑命中，是降低疑虑的正向证据，但不能抵消其他高风险发现。",
                evidence,
                control_id="virustotal",
            )
        else:
            ctx.control("virustotal", "pass", "多引擎当前未报告已知恶意。", evidence)
            ctx.add(
                "VirusTotal",
                "info",
                "VirusTotal 未发现恶意命中",
                "样本已有一定公开历史，最新多引擎扫描无恶意或可疑命中，但这不是安全保证。",
                evidence,
                control_id="virustotal",
            )


def assess_virustotal_history(
    attrs: dict[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    current = now or datetime.now(UTC)
    first_timestamp = int(attrs.get("first_submission_date") or 0)
    last_submission_timestamp = int(attrs.get("last_submission_date") or 0)
    last_analysis_timestamp = int(attrs.get("last_analysis_date") or 0)
    first = datetime.fromtimestamp(first_timestamp, UTC) if first_timestamp else current
    age_days = max(0, (current - first).days)
    maturity = (
        "very_new"
        if age_days < 30
        else "new"
        if age_days < 180
        else "mature"
        if age_days >= 730
        else "established"
    )
    votes = attrs.get("total_votes") if isinstance(attrs.get("total_votes"), dict) else {}
    return {
        "historyMaturity": maturity,
        "ageDays": age_days,
        "firstSubmissionDate": timestamp_iso(first_timestamp),
        "lastSubmissionDate": timestamp_iso(last_submission_timestamp),
        "lastAnalysisDate": timestamp_iso(last_analysis_timestamp),
        "timesSubmitted": int(attrs.get("times_submitted") or 0),
        "uniqueSources": int(attrs.get("unique_sources") or 0),
        "communityReputation": int(attrs.get("reputation") or 0),
        "communityVotes": {
            "harmless": int(votes.get("harmless", 0)),
            "malicious": int(votes.get("malicious", 0)),
        },
    }


def timestamp_iso(value: int) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat() if value else ""


def virustotal_evidence(
    stats: dict[str, object],
    history: dict[str, object],
) -> str:
    votes = history["communityVotes"]
    return "\n".join(
        [
            f"最新引擎统计：恶意 {int(stats.get('malicious', 0))}，可疑 {int(stats.get('suspicious', 0))}，"
            f"无命中 {int(stats.get('undetected', 0))}，无害 {int(stats.get('harmless', 0))}",
            f"首次提交：{history['firstSubmissionDate'] or '未知'}（约 {history['ageDays']} 天前）",
            f"最近提交：{history['lastSubmissionDate'] or '未知'}",
            f"最近扫描：{history['lastAnalysisDate'] or '未知'}",
            f"提交次数：{history['timesSubmitted']}；独立来源：{history['uniqueSources']}",
            f"社区信誉：{history['communityReputation']}；投票：无害 {votes['harmless']}，恶意 {votes['malicious']}",
            "说明：时间历史与最新扫描结果是信誉信号，不能证明历史期间从未出现问题，也不能抵消其他高风险证据。",
        ]
    )


def match_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}=(.+)$", text, re.M)
    return match.group(1).strip() if match else None
