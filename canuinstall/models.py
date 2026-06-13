from __future__ import annotations

from dataclasses import asdict, dataclass, field


ASSESSMENT_CATALOG = [
    {
        "id": "malware",
        "title": "恶意与静态安全",
        "items": [
            ("virustotal", "多引擎恶意信誉"),
            ("local_av", "本地杀毒引擎"),
            ("binary_hardening", "二进制架构与运行时加固"),
        ],
    },
    {
        "id": "publisher",
        "title": "发布者与产品信誉",
        "items": [
            ("signature", "代码签名完整性"),
            ("publisher_identity", "开发者身份与 Team ID"),
            ("gatekeeper", "Apple 公证与 Gatekeeper"),
            ("source_reputation", "下载来源与官网一致性"),
            ("product_reputation", "公开项目维护与社区信号"),
        ],
    },
    {
        "id": "system",
        "title": "系统影响与高权限能力",
        "items": [
            ("persistence", "后台常驻与持久化"),
            ("scripts", "安装脚本与系统修改"),
            ("entitlements", "系统扩展、驱动与动态代码能力"),
            ("static_indicators", "危险执行与进程控制特征"),
        ],
    },
    {
        "id": "data_security",
        "title": "数据访问、安全与隐私",
        "items": [
            ("privacy", "摄像头、麦克风等隐私权限"),
            ("file_access", "文件与目录访问范围"),
            ("sensitive_data", "敏感数据采集能力"),
            ("data_transmission", "数据外传与云同步线索"),
            ("local_data_protection", "本地存储与加密保护"),
            ("telemetry_tracking", "遥测、崩溃上报与追踪 SDK"),
            ("privacy_manifest", "Privacy Manifest 与传输安全"),
        ],
    },
    {
        "id": "supply_chain",
        "title": "供应链与第三方组件",
        "items": [
            ("components", "Framework 与动态库清单"),
            ("bundled_runtimes", "Electron、Chromium、Qt、Python 等运行时"),
            ("dependency_manifests", "依赖清单与锁文件"),
            ("vulnerabilities", "第三方组件漏洞匹配"),
            ("update_framework", "自动更新框架"),
        ],
    },
    {
        "id": "behavior",
        "title": "轻量动态验证",
        "items": [
            ("dynamic_analysis", "受控运行与系统行为观察"),
            ("network_behavior", "运行时网络与文件活动"),
        ],
    },
]

CONTROL_ACTIONS = {
    "signature": "核对签名中的发布者名称和 Team ID 是否与官网一致；一致且签名校验通过即可放行此项。",
    "gatekeeper": "在测试机执行 Gatekeeper 评估，并确认结果为 accepted；若只因挂载位置无法判断，可复制到本地临时目录后重试。",
    "product_reputation": "确认厂商仍提供安全更新、下载页可访问且当前版本受支持；不要求以知名度作为放行条件。",
    "privacy": "对照软件实际业务用途核对权限。只批准功能必需的摄像头、麦克风、屏幕或通讯录权限，并在首次运行时拒绝无关权限。",
    "file_access": "确认访问范围是否由用户主动选择，以及是否需要写入。广泛目录写入或沙箱绝对路径例外应由安全人员核对。",
    "entitlements": "重点核对系统扩展、DriverKit、网络扩展、关闭库校验、未签名可执行内存和调试附加能力；普通 App Sandbox 无需人工处理。",
    "persistence": "检查 LaunchAgent、LaunchDaemon、登录项、特权辅助程序或系统扩展的名称、签名和用途；非产品核心功能应禁止安装。",
    "scripts": "打开命中的脚本行，确认下载地址、落盘路径和执行命令。下载后直接交给 Shell、关闭安全机制或添加信任证书应直接拒绝。",
    "static_indicators": "只核对实际命中的高影响 API。确认其是否为软件核心功能；代码注入、跨进程控制或信任证书修改与业务无关时拒绝。",
    "sensitive_data": "将声明/API 线索与产品功能和隐私政策逐项对应；无法解释的屏幕、键盘、钥匙串或剪贴板读取应在受控环境验证。",
    "data_transmission": "普通联网能力无需逐项人工确认。仅在涉及敏感数据、云同步或未知域名时，执行限时网络观察并核对目标域名。",
    "local_data_protection": "在测试账户运行后检查缓存、日志和数据库是否包含明文敏感数据；企业凭据应使用 Keychain 或等效加密保护。",
    "telemetry_tracking": "确认遥测默认状态、采集字段、接收域名、保留期限和关闭方式；包含文件内容、用户名或设备唯一标识时需安全审批。",
    "privacy_manifest": "将 Privacy Manifest 声明与隐私政策核对；声明追踪或关联身份的数据必须符合企业数据政策。",
    "components": "组件清单仅用于留档，不需要逐个动态库人工复核；只有识别出已知漏洞、异常签名或非预期加载路径时才升级处理。",
    "bundled_runtimes": "确认捆绑运行时版本仍受维护即可；运行时本身不构成人工复核理由。",
    "dependency_manifests": "依赖清单用于后续 SBOM/CVE 自动匹配，不要求人工逐项阅读。",
    "vulnerabilities": "接入版本识别和 CVE 数据后自动判断；当前未执行时，不应让审批人员手工搜索全部依赖。",
    "update_framework": "核对更新包是否使用 HTTPS、是否验证签名、更新域名是否属于厂商；满足三项即可通过。",
    "dynamic_analysis": "仅对静态初筛未发现高风险的软件，在无真实数据、无管理员权限的专用测试账户中限时运行 60–120 秒。高风险或未知来源软件应改用 macOS 虚拟机。",
    "network_behavior": "受控运行时记录进程、文件写入、DNS/连接目标和系统日志；只对未知域名、敏感目录访问或异常子进程进行人工判断。",
}

CONTROL_METHODS = {
    "virustotal": "计算文件 SHA-256，通过 VirusTotal API 查询已有多引擎报告、首次/最近提交时间、扫描时间、提交次数和社区信誉。只查询哈希，不上传文件；无记录或历史很短时作为轻微不确定性信号。",
    "local_av": "如果本机可找到 clamscan，则递归扫描安装包或展开内容；未安装 ClamAV 时明确标记为未执行。",
    "binary_hardening": "识别 Mach-O 文件与 arm64/x86_64 架构，并通过 codesign 信息抽样检查 Hardened Runtime。",
    "signature": "使用 codesign --verify 或 pkgutil --check-signature 验证签名完整性和 PKG 信任链。",
    "publisher_identity": "从签名中提取 Developer ID、证书 Authority 和 Team ID，用于确认发布者身份。",
    "gatekeeper": "调用 macOS spctl，以系统 Gatekeeper 策略检查应用是否被接受及是否具备可用公证结论。",
    "source_reputation": "对本地上传文件核对用户提供的官网；不根据厂商知名度主观评分，也不自动下载软件。",
    "product_reputation": "仅在提供具体 GitHub 仓库时查询维护时间、归档状态、许可证和公开采用信号。",
    "persistence": "扫描 LaunchAgent、LaunchDaemon、登录项、特权辅助程序、系统扩展和 SUID 文件。",
    "scripts": "静态读取安装脚本，匹配联网下载后执行、修改安全机制、证书、代理、DNS、hosts 和权限等规则。",
    "entitlements": "解析代码签名 Entitlements，关注系统扩展、DriverKit、网络扩展、JIT、库校验和调试附加能力。",
    "static_indicators": "抽样扫描 Mach-O 字符串和 API，识别代码注入、跨进程控制、全局事件监听和证书修改等高影响能力。",
    "privacy": "解析 Info.plist 的摄像头、麦克风、屏幕录制、辅助功能、通讯录、日历、位置等用途声明。",
    "file_access": "解析沙箱文件访问 Entitlements、桌面/文稿/下载目录用途声明，以及二进制中的敏感路径线索。",
    "sensitive_data": "结合 Info.plist 正式声明和敏感 API 字符串，识别屏幕、剪贴板、钥匙串、联系人等数据访问能力。",
    "data_transmission": "扫描上传、WebSocket、gRPC、CloudKit、S3 和网盘组件等静态传输线索；不把普通联网能力当作已外传。",
    "local_data_protection": "识别 SQLite、Core Data、Realm、UserDefaults 等存储线索，以及 CryptoKit、Keychain、SQLCipher 等保护能力。",
    "telemetry_tracking": "识别 Sentry、Crashlytics、Firebase Analytics、Amplitude、Mixpanel 等遥测或崩溃上报组件。",
    "privacy_manifest": "解析 PrivacyInfo.xcprivacy 的数据收集与追踪声明，并检查 App Transport Security 是否被全局放宽。",
    "components": "盘点 Framework 和动态库并写入报告，作为 SBOM 与漏洞匹配输入；数量本身不计为风险。",
    "bundled_runtimes": "识别 Electron、Chromium、Qt、Python、Node.js、Java 等捆绑运行时。",
    "dependency_manifests": "查找 package-lock、Cargo.lock、requirements.txt 等依赖与锁文件，供后续 SBOM 使用。",
    "vulnerabilities": "当前仅预留控制项；可靠判断需要组件名称、精确版本与 CVE 数据源匹配，因此暂不自动下结论。",
    "update_framework": "识别 Sparkle、Squirrel、ShipIt、Google Update 等自动更新框架，后续核对签名和更新域名。",
    "dynamic_analysis": "启用 Tart 时，从指定基础镜像创建一次性 macOS VM，通过只读共享目录传入样本，限时启动后采集进程、文件变化和统一日志，结束后销毁克隆。",
    "network_behavior": "在 Tart VM 内按待测进程采集 lsof 网络连接。默认使用主机隔离网络，记录连接尝试和已建立连接，但不允许未知软件直接访问互联网。",
}


SEVERITY_POINTS = {
    "info": 0,
    "low": 2,
    "medium": 7,
    "high": 15,
    "critical": 30,
}


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    points: int | None = None
    control_id: str | None = None

    def score(self) -> int:
        return self.points if self.points is not None else SEVERITY_POINTS[self.severity]


@dataclass
class AnalysisContext:
    findings: list[Finding] = field(default_factory=list)
    checks_run: set[str] = field(default_factory=set)
    checks_possible: set[str] = field(
        default_factory=lambda: {
            item_id
            for group in ASSESSMENT_CATALOG
            for item_id, _ in group["items"]
        }
    )
    metadata: dict[str, object] = field(default_factory=dict)
    controls: dict[str, dict[str, object]] = field(default_factory=dict)

    def add(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        evidence: str = "",
        points: int | None = None,
        control_id: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                category,
                severity,
                title,
                description,
                evidence,
                points,
                control_id,
            )
        )

    def control(
        self,
        control_id: str,
        status: str,
        summary: str,
        evidence: str = "",
        action: str = "",
    ) -> None:
        priority = {
            "not_run": 0,
            "unknown": 1,
            "pass": 2,
            "observe": 2.5,
            "review": 3,
            "risk": 4,
        }
        previous = self.controls.get(control_id)
        if previous and priority.get(previous["status"], 0) > priority.get(status, 0):
            return
        if previous and previous["status"] == status:
            summaries = [previous["summary"]]
            if summary and summary not in summaries:
                summaries.append(summary)
            evidence_parts = [part for part in (previous["evidence"], evidence) if part]
            self.controls[control_id] = {
                "status": status,
                "summary": " ".join(summaries),
                "evidence": "\n\n".join(dict.fromkeys(evidence_parts)),
                "action": action or previous.get("action", ""),
            }
            if status != "not_run":
                self.checks_run.add(control_id)
            return
        self.controls[control_id] = {
            "status": status,
            "summary": summary,
            "evidence": evidence,
            "action": action,
        }
        if status != "not_run":
            self.checks_run.add(control_id)

    def to_report(self, source: dict[str, object]) -> dict[str, object]:
        raw_score = sum(f.score() for f in self.findings)
        score = min(100, raw_score)
        hard_block = any(f.severity == "critical" for f in self.findings)
        if hard_block or score >= 70:
            level, recommendation = "高", "拒绝或由安全团队专项复核"
        elif score >= 35:
            level, recommendation = "中高", "暂缓批准，完成人工复核"
        elif score >= 15:
            level, recommendation = "中", "可在限制条件下批准或人工复核"
        else:
            level, recommendation = "低", "未发现明显阻断项，可按企业政策审批"

        assessment = []
        assessed_count = 0
        for group in ASSESSMENT_CATALOG:
            items = []
            for control_id, title in group["items"]:
                result = self.controls.get(
                    control_id,
                    {
                        "status": "not_run",
                        "summary": "本次未执行或当前版本尚不支持。",
                        "evidence": "",
                        "action": "",
                    },
                )
                if result["status"] != "not_run":
                    assessed_count += 1
                related = [
                    asdict(finding) | {"points": finding.score()}
                    for finding in self.findings
                    if finding.control_id == control_id
                ]
                items.append(
                    {
                        "id": control_id,
                        "title": title,
                        **result,
                        "action": result.get("action")
                        or CONTROL_ACTIONS.get(control_id, ""),
                        "requiresHumanReview": result["status"] in {"review", "risk"},
                        "relatedFindings": related,
                    }
                )
            assessment.append(
                {"id": group["id"], "title": group["title"], "items": items}
            )
        coverage = assessed_count / len(self.checks_possible)
        confidence = "高" if coverage >= 0.75 else "中" if coverage >= 0.45 else "低"
        if confidence == "低" and not hard_block:
            recommendation = "证据不足，不能自动批准；请提供受支持的安装包或人工复核"
        ordered = sorted(
            self.findings,
            key=lambda f: (SEVERITY_POINTS[f.severity], f.score()),
            reverse=True,
        )
        dynamic_observation = self.metadata.get("dynamicObservation", {})
        dynamic_completed = (
            isinstance(dynamic_observation, dict)
            and dynamic_observation.get("status") in {"completed", "partial"}
        )
        limitations = [
            (
                "本报告包含一次性 Tart VM 中的限时动态观察；没有自动执行需要管理员授权的安装脚本。"
                if dynamic_completed
                else "本次未成功启动应用执行动态观察，也没有执行安装脚本。"
            ),
            "未观察到的行为仍可能在登录、授权、更新、用户交互或更长运行时间后出现。",
            "主机隔离网络会阻止直接互联网访问，因此动态结果不能证明软件在联网环境下没有外传行为。",
            "数据安全线索表示软件具备相关能力或包含相关组件，不等于已经采集、上传或泄露数据。",
            "低风险不等于软件绝对安全，最终决定仍应结合企业使用场景。",
        ]
        return {
            "version": "0.1",
            "source": source,
            "summary": {
                "score": score,
                "riskLevel": level,
                "confidence": confidence,
                "recommendation": recommendation,
                "hardBlock": hard_block,
            },
            "metadata": self.metadata,
            "assessment": assessment,
            "coverage": {
                "assessed": assessed_count,
                "total": len(self.checks_possible),
                "run": sorted(
                    key
                    for key, value in self.controls.items()
                    if value["status"] != "not_run"
                ),
                "notRun": sorted(
                    key
                    for key in self.checks_possible
                    if self.controls.get(key, {}).get("status", "not_run") == "not_run"
                ),
            },
            "findings": [asdict(f) | {"points": f.score()} for f in ordered],
            "limitations": limitations,
        }
