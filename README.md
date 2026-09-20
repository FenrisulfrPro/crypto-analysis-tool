# 密码算法分析工具

基于 Python + PySide6 开发，**跨平台**（Windows / Linux / macOS 均可直接运行），核心算法与界面完全解耦，可脱离 GUI 复用。

## 一、功能介绍

| 页签 | 功能 |
|------|------|
| ① 国密 SM2 / SM3 | SM2密钥对生成、SM3 摘要、SM2 签名（SM3withSM2）、验签、公钥加密 / 私钥解密（C1C3C2），多格式消息与文件导入 |
| ② 常用编码转换 | Base64 / Base64URL / HEX（大小写）/ UTF-8 / URL 编解码，多格式一键互转 |
| ③ 协议分析 (pcap) | 解析 pcap / pcapng：密钥协商过程时序视图 + Wireshark 式报文列表，支持 TLS / TLCP / SSH / CSSH（国密 SSH）/ HTTP / DNS 等 |
| ④ 证书分析 | 解析 PEM / DER 证书：版本、序列号、签名算法、签发者、有效期、公钥、指纹、自签名判断，兼容国密 SM2 证书 |
| ⑤ 对称加解密 | SM4 / AES（128/192/256），ECB / CBC / CFB / OFB / CTR / GCM，PKCS7 填充，随机密钥/IV 生成 |
| ⑥ 摘要 / HMAC | SM3 / MD5 / SHA-1 / SHA-224/256/384/512 一键全算，HMAC 消息认证码，支持文本 / 文件 |
| ⑦ 进制转换 | 二进制 / 八进制 / 十进制 / 十六进制 互转（默认 十进制 → 十六进制），四进制全景同屏展示，支持负号与任意精度大整数 |

### ① 国密 SM2 / SM3
- **SM2 签名** / **SM2 验签** / **SM2 加解密**。
- 支持一键生成 SM2 密钥对、SM3 摘要、SM2 签名与验签（SM3withSM2，标准国密曲线，可与其他国密实现互通验签）。
- 消息方式可选「消息M」或「Hash(Za‖M)」；编码支持 HEX / UTF-8 / Base64，可导入文件或直接拖拽。
- 签名支持 r‖s 与 DER 多格式自动识别；加解密采用 C1C3C2 输出，公钥加密 / 私钥解密。

### ② 常用编码转换
- 输入格式支持「自动识别」，在本页粘贴任意 Base64 / Base64URL / HEX / UTF-8 / URL 编码串，选择输入/输出格式后一键互转。

### ③ 协议分析
- 支持点击「选择 pcap / pcapng 文件」或直接把文件拖到本页加载（基于 scapy 解析）。
- 两种视图模式：
  - **① 密钥协商过程（客户端 ⇄ 服务端）**：以时序卡片展示 TLS / TLCP / SSH / CSSH 握手交互。TLS/TLCP 显示 ClientHello → ServerHello → 证书链 → 密钥交换 → Finished 全过程及加密套件、SNI/ALPN、证书链（含国密 SM2 证书）；支持 TLCP **双向身份鉴别**、SSH 展示 KEXINIT 协商的**双端选定算法**（密钥交换/加密/MAC/压缩/主机密钥）；CSSH（国密 SSH）展示完整国密协商过程与 SM2 验签结论（见下）。
  - **② 报文列表（Wireshark 式）**：逐包明细表，点击任意行弹出完整协议字段树（Ethernet / IP / TCP / UDP / ICMP / ARP / DNS / HTTP / SSH / TLS / TLCP），SSH 包自动标注客户端/服务端角色，可查看 TCP 流原文（Hex + ASCII）。
- 支持协议下拉过滤 + 关键字条件搜索、导出 CSV。
- **CSSH 国密 SSH 专项解析（GM/T 0129-2023）**：Wireshark 等工具无法识别 CSSH（只能看到 TCP），本工具直接深入 TCP 负载字节流检索并重组 CSSH 会话，在「① 密钥协商过程」视图中绘制完整国密握手时序：
  - **协商时序**：版本交换 → KEXINIT（Cookie + 算法列表）→ KEX_REQUEST（random-client）→ KEX_REPLY（服务端双证书 + random-server + SM2 签名）→ KEX（enc(K) 加密主密钥）→ NEWKEYS，每张卡片标注真实抓包包号；
  - **双证书解析**：从 KEX_REPLY 按「签名证书 ∥ 加密证书」提取服务端国密双证书（GM/T 0015 / GB/T 35276），卡片内可查看每张证书详情并一键导出 `.cer`；
  - **SM2 验签（密钥协商有效性验证）**：用签名证书公钥对 M = random-client ∥ random-server 做 SM2 验签（GB/T 35276 DER 签名，用户标识 1234567812345678），协商总结与 KEX_REPLY 卡展示签名值、待签名数据、公钥与验签结论；
  - 协商总结中**只对国密算法高亮显示**（SM2-SM3、curvesm2、SM4、CBC-MAC、HMAC-SM3 等），非国密算法保持普通文本。

### ④ 证书分析
- 打开或拖拽 PEM / DER 证书文件（或在输入框粘贴 PEM 文本），点击「解析」。
- 输出版本、序列号、签名算法、签发者、有效期、公钥、指纹、自签名判断；兼容国密 SM2证书。
- 分析结果表格支持**右键复制**（复制该值 / 复制该行 / 复制全部）；可以导出分析结果。

### ⑤ 对称加解密 SM4 / AES
- 算法：SM4 / AES；密钥位长 128 / 192 / 256 位。
- 模式：ECB / CBC / CFB / OFB / CTR / GCM（PKCS7 填充），支持随机密钥 / IV 生成，GCM 模式下可配置 Tag / AAD 认证数据。
- 输入编码 HEX / UTF-8 / Base64 可选，可导入文件或拖拽。

### ⑥ 摘要 / HMAC
- 数据来源：文本（HEX / Base64 / UTF-8 自动识别）或文件（原始字节）。
- 点击「计算全部摘要」一次性输出 SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 全部结果。
- 支持 HMAC 消息认证码：选择算法 + 输入密钥后计算。
- 结果表格支持**右键复制**（复制该值 / 复制该行 / 复制全部摘要）；HMAC 结果可**右键复制**。

### ⑦ 进制转换
- 二进制 / 八进制 / 十进制 / 十六进制 互转，默认 **十进制 → 十六进制**。
- 转换后同屏展示四种进制全景（目标进制置顶）；HEX 大写并按字节对齐补零，二进制按 8 位一组空格分隔。
- 支持负号直传、任意精度大整数；输入自动去除空格 / 下划线 / 千分位逗号，兼容 0x / 0b / 0o 前缀，非法字符给出中文提示。

## 二、使用方法

1. 启动程序后，在窗口上方页签栏选择要使用的模块。
2. **输入**：多数模块支持直接在输入区粘贴文本（HEX / UTF-8 / Base64），也可点击「选择文件 / 拖拽导入…」按钮或直接把文件拖入窗口。
3. **计算 / 解析**：点击各页的转换 / 签名 / 验签 / 加密 / 解密 / 解析 / 计算摘要等操作按钮。
4. **结果**：逐字节审查可看输入区下方的「字节数 / 前若干字节」提示；表格结果支持右键复制。
5. 协议分析流程：打开 pcap → 选择视图模式 → ① 模式点「协商过程总结 / 关键参数」查看握手时序与协商算法（CSSH 国密 SSH 抓包会自动识别并展示国密协商过程、双证书与 SM2 验签结论），② 模式点击报文行查看字段树，可用顶部过滤下拉框与搜索框缩小范围。
6. 任意时刻可用各页「清空」按钮复位（协议分析页同时清空统计、表格与物联时序图）。
7. 进制转换：选择源 / 目标进制（默认 十进制 → 十六进制），粘贴整数值后点击「转换」，结果区同屏展示四种进制全景，可一键复制。

## 三、不同系统的运行方式

环境要求：**Python 3.9+**与 pip。依赖清单见 `requirements.txt`（PySide6、gmssl、scapy、cryptography、matplotlib）。

### Windows
- 双击 `run.bat` 一键启动：自动检查 Python 与依赖，首次运行自动 `pip install -r requirements.txt`，随后启动主程序。
- 或手动运行：
  ```bat
  pip install -r requirements.txt
  python main.py
  ```

### Linux（Ubuntu / Debian 等桌面发行版）
- 双击 / 执行 `run.sh` 一键启动（自动检查并安装依赖）：
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
- 或手动运行：
  ```bash
  python3 -m pip install -r requirements.txt
  python3 main.py
  ```
- 注意：需在图形会话（X11 / Wayland）中运行；若报 Qt 缺少系统库，先安装：
  ```bash
  sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libegl1
  ```

### 预编译绿色包（无需 Python 环境）
- 获取方式：GitLab「构建 → 流水线 → 对应作业 → 下载产物」，或 GitHub「Actions → build-packages → 对应运行 → Artifacts」。
- **Linux x86_64 绿色包**（面向凝思 Linx / Debian 10，glibc ≥ 2.28，X11 桌面）：
  ```bash
  tar -xzf CryptoAnalysisTool-linux-x86_64.tar.gz
  cd CryptoAnalysisTool
  ./CryptoAnalysisTool
  ```
  该包已随包携带 `libxcb-cursor.so.0`（取自 Debian 10 官方仓库，glibc 2.8）及其余 xcb 平台库，
  CI 通过 `ldd` 自包含门禁与 Xvfb 下真实加载 xcb 插件冒烟，正常无需再装系统库。
  若仍提示 `Could not load the Qt platform plugin "xcb"`，说明目标机缺少基础图形库，可安装：
  ```bash
  sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libgl1 libegl1
  ```
- **Windows 绿色包**：解压 `CryptoAnalysisTool-win-x64.zip`，双击 `CryptoAnalysisTool.exe` 即可。

### macOS
- 手动运行（与 Linux 相同）：
  ```bash
  python3 -m pip install -r requirements.txt
  python3 main.py
  ```

### 无显示环境（仅自检 / 服务端）
- Linux 无头环境可加 `QT_QPA_PLATFORM=offscreen` 做启动自检（不做界面显示）：
  ```bash
  QT_QPA_PLATFORM=offscreen python3 main.py
  ```

## 四、目录结构

```
CryptoAnalysisTool/
├── main.py                  # 主程序（PySide6 界面，七个页签）
├── run.bat                  # Windows 一键启动脚本（自检依赖）
├── run.sh                   # Linux 一键启动脚本（自检依赖）
├── requirements.txt         # Python 依赖清单
└── modules/
    ├── sm2_sm3.py           # 国密 SM2 密钥/签名/验签/加解密、SM3 摘要、多格式签名公钥归一化
    ├── codec.py             # 常用编码转换核心逻辑
    ├── radix.py             # 进制转换核心（二/八/十/十六进制互转，任意精度整数）
    ├── sym_crypto.py        # SM4 / AES 对称加解密（ECB/CBC/CFB/OFB/CTR/GCM + PKCS7）
    ├── hash_tools.py        # SM3/SHA 族/MD5 摘要 + HMAC 核心逻辑
    ├── pcap_analysis.py     # pcap 协议分析（包统计/分布/明细、协议过滤搜索、SSH 报文列表反标）
    ├── cert_analysis.py     # X.509 证书分析核心逻辑（兼容国密 SM2 曲线 1.2.156.10197.1.301）
    ├── tls_parser.py        # TLS / TLCP 明文握手深度解析（记录/握手切分、TCP 流按 seq 重组、ClientHello/ServerHello 加密套件与 SNI/ALPN 扩展、证书链含国密 SM2 证书、ServerKeyExchange、Client⇄Server 双向流重组、TLCP 拨号业务通道前置报文跳过）
    ├── cssh_parser.py       # CSSH 国密 SSH（GM/T 0129-2023）解析：TCP 负载识别 CSSH-1.0 会话、传输层分帧重组、KEXINIT/KEX_REQUEST/KEX_REPLY/KEX 解析、服务端双证书提取、SM2 验签（随机数 ∥ 签名值）与国密算法高亮
    ├── handshake_view.py    # 握手时序图：TLS/TLCP/SSH/CSSH 协商事件、协商结果汇总（含 SSH 双端协商算法、CSSH 双证书/验签/国密算法高亮）
    ├── handshake.py         # 握手消息解析辅助
    └── packet_parser.py     # 单包全层字段树（Ethernet/IP/TCP/UDP/ICMP/DNS/HTTP/SSH/TLS/TLCP）+ 全 TCP 流级解析（含 SSH/CSSH 客户端/服务端方向判定）+ Hex+ASCII 转储
```

## 五、说明

- SM2 采用标准国密曲线，签名算法 SM3withSM2，可与其他国密实现互通验签。
- 核心算法与界面完全解耦，`modules/` 下均为纯 Python 逻辑，可脱离 GUI 复用或二次开发。
- CSSH 国密 SSH 解析依据 GM/T 0129-2023：自动定位 `CSSH-1.0` 会话、按 RFC 4253 分帧重组，提取服务端双证书并完成 SM2 验签（验签依赖 `gmssl`；未安装时结论显示为「未能验签」并提示，不影响其余解析）。
