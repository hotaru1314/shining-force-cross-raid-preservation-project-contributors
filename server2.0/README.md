# server 2.0 —— Shining Force Cross Raid 双机联机假服务端

> 交付版｜2026-11-07｜基于 2026-11-07 09:45 的验证版本打包
> 现状：**两台真机可进同一对局，互相看见、动作同步、名字与装备正确、1P/2P 正确、整局跑完并正常写卡。**

---

## 1. 这是什么

一台 Windows 机器上跑的"假服务端"，替代 SEGA 的五个服务，让两台街机柜互相联机：

| 服务 | 端口 | 作用 |
|---|---|---|
| `allnet_server.py` | TCP 80 | ALL.Net（投递/认证/存档） |
| `match_server.py` | TCP 52000 | SIF 匹配大厅（含 `coop` 组队与 CC 下发） |
| `pcp_server.py` | TCP 40100/40102/40104/40106/40110/40113/40114 | PCP 钥匙芯片（含 `ssd.proof`） |
| `udp_echo.py` | UDP 52002 | SIF ping（"全国"灯） |
| `udp3953.py` | UDP 3953 | 对局数据（SCTP-over-UDP，按真机抓包回放 + 状态转发） |

## 2. 已验证状态（2026-11-07）

```
09:47:16 – 09:55:20   一整局，484 秒，29,863 个 UDP 包，两台全程在线
两台各用各的下行模板（0x10400024 / 0x10400025），1P/2P 正确
对方的名字与装备正确（档案按 subject 填充，off37 跟随）
09:54:50              C:\iccard.bin 写卡成功（4019B）
异常：无（日志里的 WSAECONNRESET 是客户端每次查命令就断开的固有行为，属噪音）
```

## 3. 前置条件

1. 本机网卡 IP = `config.json` 里的 `server_ip`（默认 `10.0.0.10`）；
2. 两台机台的 ALL.Net / SIF 地址指向这台机（DNS 或 hosts）；
3. **以管理员身份**启动（`allnet` 要占 80 端口）；
4. 两台机台的 keychip 号必须不同。格式由客户端硬校验（`sub_E3FBD0`），不是我们的约定：

   | 位置（0 基） | 要求 |
   |---|---|
   | `0..3` | 数字或大写字母（**不含 I / O**） |
   | `4` | 必须是 `-` |
   | `5..7` | 数字或大写字母（**不含 I / O**） |
   | `8..15` | **只能是数字** |
   | 长度 | 正好 16 字符，第 17 字节为 0 |

   示例（**假号，只示范格式**）：`AALG-00000000101`；客户端上报的 serial = 去掉 `-` 取前 11 位。

## 4. 启动 / 停止

```powershell
# 启动（管理员 PowerShell）
cd server2.0
.\python\python.exe run_server.py

# 查看状态（注意：3953 显示 -- 是 SO_REUSEADDR 导致的假阴性，用 netstat 复核）
.\python\python.exe run_server.py --status
netstat -ano -p UDP | findstr 3953

# 停止
.\python\python.exe run_server.py --stop
```

日志：`logs\server.log`（各服务汇总）、`data\*.log`（分服务）。

## 5. 运行开关（`data\` 下的标记文件：存在 = 生效）

| 文件 | 作用 | 默认 |
|---|---|---|
| `relay_state.on` | 转发两台对局状态（位置/动作同步） | **开**（别删） |
| `world_replay.on` | 按真机时间轴回放世界流 | **开**（别删） |
| `echo_start_fixed.on` / `fill_start_u32.on` | ALL.Net 报文修正 | **开**（别删） |
| `profile_identity.off` | 建了 = **关闭**档案身份覆盖（画面退回抓包内容） | 无 |
| `skip_bigsnap.on` | 建了 = 不回放 400~1200B 世界快照（实验用，实测无变化） | 无 |
| `relay_skip_replay.on` | 建了 = 跳过开场帧，**会进不了 stage**，仅 A/B 用 | 无 |


### 5.1 假队友（`--coop-fake`）

**这不是 `data\` 开关，而是 `config.json` 里 sif 服务的启动参数**：

```json
"services": {
  "sif": {
    "args": ["--bind", "0.0.0.0", "--port", "52000", "--hold", "40", "--coop-fake"]
  }
}
```

行为（`coop.py::sync_fake`）：

| 情况 | 结果 |
|---|---|
| 队伍里只有 1 个真人 | 塞入一个假队友（句柄 `0x1040002F`，槽位表外，**不占真人号**），计数 1/4 → 2/4，正常开场 |
| 第 2 个真人加入 | 自动撤掉假队友 |
| 真人全走了 | 整队清空，下一局重新判断 |

**常见症状**：单人进匹配一直停在 `参加者を探しています… 1/4` ——
八成是 `--coop-fake` 没带上。看 `data\match_server.log` 里有没有这行：

```
coop: 单人 -> 已塞入假队友 handle=0x1040002F
```

---

## 6. 两台怎么分 1P / 2P

`data\leader_ip.txt`（没有则默认 `10.0.0.10`）指定的那台拿 `0x10400024` = **房主 = 1P**。
依据：真机抓包里"成员记录帧"的第二格永远是 `0x10400024`。

## 7. 已知限制

- 外观/装备跟随玩家档案（1264B）；世界快照里仍带录像中的外观，但实测不影响显示；
- 单台机也能进"双人局"（回放出来的假队友，句柄 `0x1040002F`），用于单人调试；
- **重启服务端会让大厅连接变孤儿**：客户端会停在只发心跳、再按准备也上不去，
  只能重启游戏进程（街机上意味着重走投币流程）→ **改代码可以随时改，重启要攒批、且先确认没人正在玩**；
- 一局结束后客户端回菜单，服务端无需重启即可再来一局。

## 8. 目录

```
server2.0\
  run_server.py              进程管理（读 config.json 起五个服务）
  config.json                **唯一真相源**：IP / 端口 / keyid / flags
  allnet_server.py           ALL.Net
  match_server.py            SIF 大厅（调用 coop.py）
  coop.py                    组队表 / 发号 / CC(212B) / 状态帧(188B)
  coop_templates.py          大厅侧抓包模板
  pcp_server.py              PCP 钥匙芯片（ssd.proof 需要 SBVB_Table.dat）
  udp_echo.py                SIF ping（全国灯）
  udp3953.py                 对局通道（控制通道 + 世界流 + 状态转发）
  world_replay.py            按时间轴回放（含档案身份覆盖、状态转发）
  world_templates.py         主机(0x25)视角的世界流模板
  world_templates_joiner.py  加入方(0x24)视角的世界流模板
  real_frames.py             大厅侧固定帧（A2/T10/CC/ack）
  core\                      配置与日志小工具
  python\                    内置 Python 运行时（无需另装）
  data\                      运行时状态与开关（日志也在这里）
  logs\                      进程管理日志
```

## 9. 排查入口

| 现象 | 先看 |
|---|---|
| 进不了对局 | `data\udp3953.log` 有没有包；`logs\server.log` 里 `coop: join/ready`、`>>> CC ->` |
| 看不到对方 | `udp3953.log` 的 `world 重放启动 … 模板=` 两台是否不同 |
| 名字/装备不对 | `udp3953.log` 的 `档案身份 +xxxms 槽位 0x… 基板=… 名=…` 四行 |
| 1P/2P 反了 | `data\leader_ip.txt` 指向哪台 |
| 弹 `ERROR 0949` | `data\pcp.log` 搜 `ssd.proof` —— 这是 **SSD 证明应答**的问题，不是基板号问题（详见 §3 的格式校验说明） |

## 10. 来源与文档

- 协议规格：仓库根目录的 `../spec.md`（ESCTP / 应用层 / 各接口）
- 基板 ID 规则：见 `spec.md` §15 与本文 §6

## 11. 合规说明

- 本仓库**不包含任何游戏本体、ROM、美术/音频资源**；
- `world_templates.py` / `world_templates_joiner.py` 是**协议层回放数据**
  （每个 UdpFrame 的载荷就是当时链路上的字节：坐标、序号、句柄），
  不含模型、贴图、音乐，也不含任何可执行代码；
- `config.json` 里的 IP 与基板号都是**示例值**，与任何真实机台无关；
- 本项目的用途是**已停运街机的保存与研究**。请自行确保使用场景合法。

## 12. 依赖

只用 Python 标准库（`socket` / `threading` / `struct` / `zlib` / `json` / `http.server`）。
`python\` 目录是本机运行时快照，**可以删掉**，改用系统 Python 3.10+ 直接跑。
