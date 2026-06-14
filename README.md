# CanUInstall

CanUInstall 是一个本地优先的 macOS 软件准入评估工具。上传公开软件的
`.dmg`、`.pkg` 或 `.zip` 安装包后，它会检查恶意信誉、签名与公证、系统影响、
数据安全与隐私、第三方组件，并生成带证据的风险报告。

文件默认只在本机分析。VirusTotal 仅按 SHA-256 查询已有报告，不上传文件；
启用 Tart 后，应用只会在一次性 macOS 虚拟机中启动。

## 系统要求

- macOS
- Python 3.11 或更高版本
- Homebrew（仅 Tart、ClamAV 等可选增强能力需要）
- Apple Silicon Mac（仅 Tart 动态分析需要）

项目目前只使用 Python 标准库，没有第三方 Python 运行时依赖。
`requirements.txt` 仍然保留，以便安装脚本、编辑器和自动化工具使用统一入口。

## 最快开始

```bash
git clone git@github.com:xstrace/CanUInstall.git
cd CanUInstall
./scripts/setup.sh
./scripts/run.sh
```

浏览器打开 <http://127.0.0.1:8765>。

`setup.sh` 会检查 Python 版本、创建 `.venv`，并执行：

```bash
.venv/bin/python -m pip install -r requirements.txt
```

由于当前依赖列表为空，这一步不会下载 Python 包。

也可以手动启动：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

## 可选增强能力

### VirusTotal

1. 注册或登录 [VirusTotal](https://www.virustotal.com/)。
2. 打开 [API Key 页面](https://www.virustotal.com/gui/my-apikey)。
3. 启动 CanUInstall，在“环境与配置”中填入 API Key。

密钥只写入本机项目目录下的 `.env.local`，文件权限为 `600`，不会被页面或 API
回显。也可以通过环境变量配置：

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
./scripts/run.sh
```

VirusTotal 公共 API 的额度和使用条款可能变化，企业使用前请阅读
[官方 API 文档](https://docs.virustotal.com/docs/api-overview)。

### Tart 隔离动态分析

Tart 需要 Apple Silicon，并会下载体积较大的 macOS 虚拟机镜像。自动准备：

```bash
./scripts/setup.sh --with-dynamic
```

脚本会：

1. 通过 Homebrew 安装 Tart。
2. 下载 `ghcr.io/cirruslabs/macos-tahoe-base:latest` 为 `tahoe-base`。
3. 克隆专用的 `canuinstall-runtime`。
4. 在专用镜像内安装 osquery。

完成后可检查：

```bash
tart list
```

页面“环境与配置”中应显示 Tart、`canuinstall-runtime`、osquery 和 eslogger 可用。
动态分析会从运行时镜像创建一次性克隆，使用只读文件共享和 Tart Softnet。
虚拟机可以访问公网以观察 DNS/IP，同时默认阻止私网目标；分析结束后删除克隆。更多信息见
[Tart 官方快速入门](https://tart.run/quick-start/)。

如需自定义镜像：

```bash
TART_IMAGE="ghcr.io/example/image:tag" \
TART_BASE_SOURCE_VM="my-base" \
TART_RUNTIME_VM="canuinstall-runtime" \
./scripts/prepare-tart-runtime.sh
```

### ClamAV

```bash
./scripts/setup.sh --with-clamav
```

安装后，CanUInstall 会自动执行本地已知恶意内容扫描。缺失 ClamAV 不会阻止其余
静态评估。

## 当前能力

- SHA-256、文件类型、大小和基础元数据
- Apple 代码签名、Team ID、公证、Gatekeeper、Entitlements 与 Hardened Runtime
- 安装脚本、持久化、系统扩展、驱动和危险执行线索
- 摄像头、麦克风、文件目录、屏幕、剪贴板、Keychain 等数据访问能力
- 数据传输、本地存储与加密、遥测 SDK、Privacy Manifest 和 ATS
- Framework、动态库、捆绑运行时、更新框架和依赖清单
- VirusTotal 多引擎结果、样本首次出现时间和社区信誉
- Tart 虚拟机内的进程树、文件操作、网络活动和统一日志观察
- 风险评分、置信度、人工复核建议、Markdown/HTML 报告导出

## 安全边界

- DMG 只读挂载，临时目录会在分析后清理。
- 不会自动安装或执行 PKG 安装脚本。
- 动态分析使用 Softnet 隔离公网访问并阻止私网目标，但限时观察仍可能遗漏延迟行为。
- 静态线索表示软件具备某种能力，不等于已经采集、上传或泄露数据。
- 低风险不是绝对安全证明，最终决定仍应结合企业使用场景和政策。

## 测试

```bash
.venv/bin/python -m unittest discover -s tests -v
```

未创建虚拟环境时也可以使用：

```bash
python3 -m unittest discover -s tests -v
```
