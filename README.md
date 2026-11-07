# Shining Force Cross Raid — 联机复活 & ESCTP 逆向

**中文** · [English](#english)

> 一台 2010 年出厂的 SEGA RingEdge 街机，官方服务早已停运。
> 现在，**两台真机可以重新进入同一个对局、互相看见、打完一整局，并正常写卡**。
>
> 支撑这件事的，是从零逆向出来的 **ESCTP** —— SEGA 私有的「**SCTP over UDP**」传输层。
> 公开资料里没有任何文档：没有规范、没有开源实现、客户端连日志都是空的。

---

## ✨ 这个项目做了什么

| 亮点 | 说明 |
|---|---|
| 🔬 **逆向了一整个传输层** | ESCTP = 带 SCTP 语义（TSN / SSN / SACK / 分片）的用户态协议，跑在 UDP 上。`spec.md` 记录了帧格式、chunk 类型、可靠传输的四条契约、真机时序，以及 10 条"每条都烧过钱"的踩坑 |
| 🖥 **写了一台假服务端** | ALL.Net（TCP 80）/ SIF 大厅（TCP 52000）/ PCP 钥匙芯片（4010x）/ 对局通道（UDP 3953）/ 心跳（UDP 52002），五个服务，纯 Python 标准库 |
| 🕹 **两台真机真的能联机** | 同局、1P/2P 正确、动作互相同步、对方的名字与装备正确；实测跑完 **484 秒 / 29,863 包的一整局**，结束时正常写卡 |
| 🔌 **机台侧也给了** | 启动器 + 注入辅助（假 JVS / 假读卡器 / 假钥匙芯片 / 窗口化），卡片、触摸、串口都可用 |
| 🌍 **不是只能跑这一作** | 同一份 `spEsctp Ver 0.84.03` 也出现在 *Border Break Scramble*、*Sega Rally 3*、*Cross Elysion* 里 —— 这套传输层是整个 RingEdge 世代共用的 |

## 🔍 为什么值得读（哪怕你不玩这个游戏）

- **ESCTP 没有公开资料。** 这里的每一条结论都来自静态分析与真机抓包，标注了证据；
- **"明明都对了，它就是不动"** 这一类问题，答案往往不在帧内容，而在**这是哪一层协议**；
- 协议规格 `spec.md` 是可以直接用来逆向**其它** SEGA 街机网络层的；
- 假服务端的结构（ALL.Net / SIF / PCP / 对局 四层分离）与具体游戏无关，可以照搬。

## 📖 从哪里开始

1. 只想知道结论 → [`spec.md`](spec.md)
2. 想跑起来 → [`server2.0/README.md`](server2.0/README.md) 的「快速开始」
3. 想改机台侧 → [`client/README.md`](client/README.md)

> 本项目与 SEGA 无关，不含任何游戏本体、ROM、美术或音频资源。
> 许可：代码 MIT、文档 CC BY 4.0（详见 [§7](#7-许可)）。
> 目的只有一个：**让一台已经停运的街机，还能再打一局。**

---

## 1. 里面有什么

| 路径 | 内容 |
|---|---|
| **[`spec.md`](spec.md)** | ESCTP 传输层与上层消息的逆向规格（本仓库的重点） |
| **[`server2.0/`](server2.0/)** | 可运行的假服务端：ALL.Net / SIF 大厅 / PCP 钥匙芯片 / 对局 UDP |
| **[`client/`](client/)** | 机台侧客户端包：启动器 + 注入辅助 DLL + 卡片/PCP 配置 |

两者是配套的：`spec.md` 是"为什么这样写"，`server2.0` 是"这样写能跑"。

---

## 2. `spec.md` 讲什么

- **ESCTP 的定性**：它就是 SCTP 的用户态实现，跑在 UDP 上（客户端自述 `spEsctp Ver 0.84.03`）。
  全网没有公开资料，这份是从抓包和断点里逼出来的。
- **线格式**：`[vtag][type][flags][len][body]`，以及"chunk 里还套着一层应用帧"这个坑。
- **可靠性契约**：TSN 必须连续、每个上行 DATA 必须回 SACK、重传必须复用同一块、
  有序流的 SSN 不能有缺口 —— 这四条任意一条不满足，客户端就不往前走，而且不报错。
- **PPID 的两种语义**：`sid=0` 时是载荷长度，`sid=16` 时是消息类型。
- **真机时间线**：从 INIT 到 LoadFinish 的每一跳，包括"INIT_ACK 故意慢 3.28 秒"。
- **应用层消息目录** + **最小实现清单** + **10 条踩坑表**（每条都实测过）。
- **续作对比**：Cross Elysion 与本作共用同一份 ESCTP 库，但应用层要各自重逆。
- **多作判定**：`game_id` 两作都是 `SBVB`，真正的指纹是 `firm_ver` 的**格式形状**。

---

## 3. 快速开始

```bash
# 1) 需要 Python 3.10+（只用标准库；server2.0/python/ 是本机运行时快照，可删）
cd server2.0

# 2) 改配置：server_ip 改成这台机器的网卡 IP；需要时改 keyid / mainid
#    （config.json 里是示例值，直接跑之前必须改）

# 3) 管理员权限启动（ALL.Net 要占 80 端口）
python run_server.py

# 4) 把机台的 ALL.Net / SIF 地址指向这台机器（DNS 或 hosts）
```

停止与状态：

```bash
python run_server.py --status
python run_server.py --stop
netstat -ano -p UDP | findstr 3953     # 3953 的端口，--status 会显示 -- （假阴性）
```

详细的配置项、开关、日志含义见 [`server2.0/README.md`](server2.0/README.md)。

---

## 4. 已验证到什么程度

```
两台机台   → 同一队伍 → 同一对局           ✅
场上       互相看见、动作同步               ✅
1P / 2P    正确（房主固定拿 0x10400024）    ✅
对方       名字与装备正确                   ✅
一整局     484 秒 / 29,863 包 / 零异常      ✅
结算       正常写卡（4019B）                ✅
```

**还没做的**（详见仓库内私有笔记，不在本仓库）：

- 联网档（NetData / rd2 的玩家档案字段）；
- 事件系统（`NetDataEventInfoResponse`，0x13）；
- SFC.NET 联动机制（读卡时的登録設定）；
- 卡面 6 个自定义字段的客户端改写（服务端方案已验证，但会让行为偏离真机）。

---

## 5. 目录

```
.
├── spec.md                 ESCTP 协议规格（重点）
└── server2.0/
    ├── run_server.py       进程管理：读 config.json 起五个服务
    ├── config.json         唯一配置入口（IP / 端口 / keyid / 开关）
    ├── allnet_server.py    ALL.Net        TCP 80
    ├── match_server.py     SIF 大厅        TCP 52000
    ├── coop.py             组队 / 发号 / CC(212B) / 状态帧(188B)
    ├── pcp_server.py       PCP 钥匙芯片    40100/02/04/06/10/13/14
    ├── udp_echo.py         SIF ping        UDP 52002
    ├── udp3953.py          对局通道        UDP 3953（ESCTP）
    ├── world_replay.py     按真机时间轴回放世界流 + 状态转发
    ├── world_templates*.py 世界流回放数据（链路上的字节，非资源文件）
    ├── core/               配置与日志小工具
    └── data/               运行时开关（.on 文件 = 打开）

client/                    机台侧（跑在机台上那台 Windows）
    ├── client.json         唯一配置：服务器 IP / 游戏目录 / keychip / 卡片字段
    ├── launch_client.*     启动器（生成 dnsmap → 起本机 PCP → 注入 → 起游戏）
    ├── bin/                注入用的辅助 DLL（内存补丁 / 假串口 / 窗口化 / 抓包）
    ├── cfg/                dnsmap、poke.cfg（内存补丁表）
    └── pcp/                本机假 PCP
```

---

## 6. 合规说明

- 本仓库**不包含游戏本体、ROM、美术/音频资源**，也不含任何可执行补丁；
- `world_templates*.py` 是**协议层回放数据**：每个帧的载荷就是当时链路上的字节
  （坐标、序列号、句柄）。它不含模型、贴图、音乐；
- `config.json` 里的 IP 与基板号都是**示例值**，与任何真实机台无关；
- 本项目的用途是**已停运街机的保存与研究**。使用前请自行确认所在地区的合法性。

---

## 7. 许可

**完全开源，只要署名。** 三份许可各自独立：

| 内容 | 许可 | 要求 |
|---|---|---|
| 代码（`server2.0/`、`client/`） | **MIT**（见 [`LICENSE`](LICENSE)） | 保留版权声明与许可全文即可，商用/修改/再分发都可以 |
| 文档（`spec.md`、各 `README.md`） | **CC BY 4.0**（见 [`LICENSE-docs`](LICENSE-docs)） | 注明来源与链接 |
| 抓包数据（`world_templates*.py`、`real_frames.py`） | **不在上述范围内** | 真机链路上的字节，仅供互操作研究 |

建议的署名格式：

```
基于 Shining Force Cross Raid 保存研究项目（ESCTP 逆向 / 假服务端）
https://github.com/hotaru1314/shining-force-cross-raid-preservation-project-contributors
```

> `spec.md` 里每一条结论都是实测出来的。错误引用会让后来者再走一遍弯路，
> 所以引用时请带上链接与"实测自真机"的说明。

## 8. 想帮忙？

欢迎 issue / PR，尤其是这几类：

- 补上本文 §4 里"还没做的"任何一项；
- 指出 `spec.md` 里任何一条与你的抓包不符的地方（附抓包与复现步骤）；
- 其它 SEGA RingEdge 机台的 ESCTP 抓包 —— 这套传输层应该是世代通用的。

---

<a id="english"></a>

# English

> A 2010 SEGA RingEdge arcade cabinet. Its online service was shut down years ago.
> Today, **two real cabinets can enter the same match again, see each other, play a
> full round and write their cards normally.**
>
> What makes that possible is **ESCTP** — SEGA's private **SCTP-over-UDP** transport,
> reverse engineered from scratch. There is no public documentation for it: no spec,
> no open-source implementation, and the shipped client has its logger compiled out.

## ✨ What this project contains

| 亮点 | 说明 |
|---|---|
| 🔬 **A whole transport layer, reverse engineered** | ESCTP carries SCTP semantics (TSN / SSN / SACK, fragmentation) over UDP. `spec.md` documents the wire format, chunk types, the four reliability contracts, the real-hardware timeline, and 10 pitfalls that each cost us a test run |
| 🖥 **A working fake server** | ALL.Net (TCP 80) / SIF lobby (TCP 52000) / PCP keychip (4010x) / match channel (UDP 3953) / heartbeat (UDP 52002) — five services, pure Python standard library |
| 🕹 **Two cabinets, actually playing** | Same match, correct 1P/2P, synchronized actions, correct peer names and equipment. A full round measured at **484 s / 29,863 packets**, ending with a successful card write |
| 🔌 **The cabinet side too** | Launcher plus injection helpers (fake JVS, fake card reader, fake keychip, windowing). Cards, touch and serial all work |
| 🌍 **Not just this one game** | The same `spEsctp Ver 0.84.03` shows up in *Border Break Scramble*, *Sega Rally 3* and *Cross Elysion* — this transport is shared across the whole RingEdge generation |

## 🔍 Why it is worth reading (even if you never play this game)

- **ESCTP has no public documentation.** Every claim here comes from static analysis
  and real-hardware captures, and is tagged with its evidence;
- The class of bug that looks like *"everything is byte-identical, yet it never
  advances"* is usually not about the payload — it is about **which layer you are in**;
- `spec.md` is directly reusable for reverse engineering **other** SEGA arcade titles;
- The server layout (ALL.Net / SIF / PCP / match, four separate layers) is
  game-agnostic and can be reused as a blueprint.

## ⚖️ License

**Fully open source — attribution only.** Code under MIT, documentation under
CC BY 4.0, captured hardware data called out separately — see
[`LICENSE`](LICENSE) / [`LICENSE-docs`](LICENSE-docs).

> Not affiliated with SEGA. No game binaries, ROMs, art or audio are included.
> The only goal: **let a dead arcade cabinet play one more round.**

---
