# CLIENT.md — Shining Force Cross Raid 客户端包

> **验收：2026-10-25 用户确认客户端包跑通，B 结案。**
>
> 这是一个**客户端**包：注入 7 个 DLL、起本地 PCP、把 ALL.Net/SIF/UDP 指向你的服务器。
> 服务器端（`K:\debug\server\` 或 `.7` 上的 `D:\server\`）不在这里。

## 1. 包内容

```
client\
  bin\        tpfake / probe / connlog / windower / glcap / serialfake / touchfake .dll
              8 个可选调试钩子：appdump12 / sendlog / esctp_tap / sifdump /
              filefail / sessdump / handump / taildump，
              外加 recvlog.dll（hook recv，记录游戏实际收到的字节）
              （launch_client.ps1 -Debug / .bat --debug 才注入）
              inject_multi.exe
  cfg\        poke.cfg          （forcenet + 补丁；唯一需要改 IP 的文件之一）
              dnsmap.txt        （5 个域名 -> 服务器 IP）
              comfake.txt       （假串口，默认 COM2）
              reply.hex         （串口应答）
  pcp\        pcp_server.py     （必须在本机跑：游戏只连 127.0.0.1:4010x）
  python\     python.exe + 标准库（嵌入式 3.12.8，给 pcp_server 用）
  card\       iccard_seed.bin + iccard.txt（种子卡：卡数据 + 20 位 mark；换成你自己的卡）
  logs\       运行日志（自动生成）
  shots\      glcap 截图（自动生成）
  client.json  server_ip / game_dir / exe 哈希 / PCP 端口
  launch_client.ps1     （PowerShell 路线）
  launch_client.py/.bat （CMD 路线，用包内 python，不需要 PowerShell）
  setup_card.ps1/.bat   （一次性装种子卡，需管理员）
  CLIENT.md
```

## 2. 前置条件

- Windows 10/11 x64；
- **同一版本的游戏 exe**（`project_f-ringedge-release.exe`，SHA256
  `BB2FF0E2675363377074EA422D3FBAD43C053682B2C0223A67BD7BE88A5951E5`）。
  `tpfake` 的补丁是绝对 VA，版本不同会打错地址；`launch_client.ps1` 会校验哈希。
- 不需要 K: 盘、不需要 `K:\debug`、不需要改 hosts、不需要网卡别名；
- 第一次建卡/写 `C:\iccard.bin` 需要管理员；之后普通权限即可（`setup_card.*` 会设 Low + 给当前用户 M 权限）。
  **卡是两个文件**：`C:\iccard.bin`（4019B 数据）+ `C:\iccard.txt`（20 位 mark）；缺 txt 时按 F2 会抛
  `std::runtime_error`（probe.log 里能看到 `VEH: code=0xE06D7363 ... runtime_error`）。

## 2.5 游戏放哪、怎么启动

1. 把**整个游戏目录**（`project_f-ringedge-release.exe` + `rom\` + `ram\` + `SBVB_Table.dat` +
   `glut32.dll` 等）拷到目标机，例如 `D:\Games\Shining Force - Cross Raid`。不要只拷 exe。
2. `client\` 可以放任意位置（不必和游戏同目录）。
3. `client.json` 的 `game_dir` 指向**含 exe 的那一层**：
   ```json
   "game_dir": "D:\\Games\\Shining Force - Cross Raid"
   ```
   - `client\` 就在游戏目录里面 → 写相对路径 `".."`；
   - `client\` 和游戏目录是兄弟 → 写 `"..\\Shining Force - Cross Raid"`。
4. **启动永远用 `launch_client.bat`（或 `launch_client.ps1`），不要双击游戏 exe。**
   启动器会挂起创建进程 → 注入 DLL → 再恢复；直接跑 exe 没有 JVS/ALL.Net 补丁，
   会卡在自检或网络错误（ERROR 6401 / 8005）。
5. 第一次先管理员跑 `setup_card.bat` 装种子卡；之后普通 CMD 跑 `launch_client.bat`。

## 3. 一次性准备

1. 把整个 `client\` 目录拷到目标机（路径随意）；
2. 编辑 `client.json`：
   - `server_ip`：你的服务器 IP（**只改这一行**，launcher 会自动写 `cfg\dnsmap.txt` 和 `cfg\poke.cfg` 的 `forcenet`）；
   - `game_dir`：游戏 exe 所在目录（见 2.5；绝对路径或相对 `client\` 的路径都行）；
   - `exe` / `exe_sha256` 一般不用动。
3. 准备 IC 卡（二选一）：
   - 有现成卡：管理员运行 `setup_card.bat`/`.ps1`，会把 `card\iccard_seed.bin` 复制到 `C:\iccard.bin`、
  `card\iccard.txt` 复制到 `C:\iccard.txt`（两个都要，缺 txt 会读卡失败）；
   - 想用游戏自己建卡：删掉 `C:\iccard.bin`，**以管理员身份**启动游戏，F2 -> 新規プレイ；
     建完卡执行一次 `icacls C:\iccard.bin /setintegritylevel Low`。

> 也可以不改 `client.json`，直接改 `cfg\poke.cfg` 的 `forcenet <IP>` 和 `cfg\dnsmap.txt` 的 5 行——
> 这就是"只改两行 IP"的字面做法。两种方式等价，launcher 以 `client.json` 为准并在每次启动时重写这两个文件。

## 4. 启动

**路线 A：CMD（不需要 PowerShell，推荐给干净机）**

```bat
launch_client.bat
```

它调用包内 `python\python.exe launch_client.py`，逻辑与 PowerShell 版完全一样。
也可以直接：`python\python.exe launch_client.py --server-ip 10.0.0.7 --game-dir "D:\..."`

**路线 B：PowerShell**

```powershell
powershell -ExecutionPolicy Bypass -File .\launch_client.ps1
```

两条路线都会：

1. 校验 exe 哈希；
2. 写 `cfg\dnsmap.txt` + `cfg\poke.cfg` 的 forcenet；
3. 探测远端 `:80` / `:52000`（只告警，不阻塞）；
4. 起本地 PCP（`127.0.0.1:40100/40102/40104/40106/40110/40113/40114`），
   `--networkaddr auto` 自动取本机主 IPv4，`--ds-table <game_dir>\SBVB_Table.dat`
   （`keychip.ssd.proof` 需要这张表，路径写死会 `FileNotFoundError` → 进游戏通信失败）；
5. 杀旧游戏进程，注入 `bin\tpfake.dll` + `bin\probe.dll`
   （tpfake 自己再加载 connlog/windower/glcap/probe/serialfake/touchfake）。

可选参数：`-ServerIP 10.0.0.7`、`-GameDir "D:\..."`、`-NoPcp`、`-NoLaunch`、`-Debug`（额外注入 8 个日志钩子）、`-Force`。
Python 版对应 `--server-ip` / `--game-dir` / `--no-pcp` / `--no-launch` / `--debug` / `--force`。

> 种子卡安装（管理员 CMD）：`setup_card.bat`。它不需要 PowerShell；会备份旧卡到 `card\iccard_prev.*`，
> 复制 `card\iccard_seed.bin` + `card\iccard.txt` 到 `C:\iccard.bin` + `C:\iccard.txt`，设 Low 并给当前用户 M 权限。

## 5. 验收

1. 游戏启动，**F2 插卡**，进 Game Mode Select；
2. 右上三个状态灯全绿（全国 / 店 / チーム 的连通性）；
3. 全国協力 / 店内協力 可选（蓝色「選択」）。

> **注意**：**一次剧情任务都没打过的新卡**，全国/店内会是灰的——这是卡进度门槛，不是网络问题。
> 拿一张打过至少一话剧情的卡即可。チーム/師弟 灰是正常的（需要队伍关系）。

## 6. 故障排查

| 现象 | 先看 | 处理 |
|---|---|---|
| 三灯不绿 | `logs\connlog.log` 有没有 `connect -> <server>:80/52000` | 服务器 `:80`/`:52000`/`:52002 UDP` 是否在跑；防火墙；`server_ip` |
| 三灯绿但 Online 灰 | 换一张有剧情进度的卡 | 不是网络问题 |
| 游戏报「データの作成に失敗」 | 是否普通权限启动 | 建卡必须管理员；或直接 `setup_card.ps1` |
| 卡读不出来/存不进去 | `C:\iccard.bin` + `C:\iccard.txt` 是否都在 | 重跑 `setup_card.bat`；两个文件都要 Low + 当前用户 M |
| F2 插卡后游戏抛异常/卡没反应 | `probe.log` 里 `VEH: ... runtime_error` | 缺 `C:\iccard.txt`（mark 文件）；重跑 `setup_card.bat` |
| 注入失败 | `logs\inject.err.txt` | 杀毒拦截；`bin\` 是否完整；exe 是否同版本 |
| `python.exe: can't open file ...launch_client.py` | 解压不完整 | 重新解压**整个** `client` 目录，`.bat` 和 `.py` 必须同目录 |
| PCP 起不来 | `logs\pcp.err.txt` | 4010x 被旧进程占用（`Get-NetTCPConnection -State Listen -LocalPort 40100`） |
| 进游戏「通信失败」/ 卡认证 | `logs\pcp.log` 里 `handler error: FileNotFoundError` 或 `NO HANDLER for 'keychip.ssd.proof'` | PCP 没拿到游戏的 `SBVB_Table.dat`；用新版 launcher（自动传 `--ds-table`），并先 `taskkill /F /IM python.exe` 杀掉旧 PCP 再启动 |
| 服务端说回了、游戏说没收到 | `logs\recv.log`（`--debug` 注入 recvlog 后才有） | 没有 `HTTP/1.0 200 ... x-rd2-...` 那行 ⇒ 本地网络层（Defender/防火墙/LSP）拦了；有那行但仍报错 ⇒ 游戏解析问题 |
| 游戏一启动就崩 | exe 哈希 | 换回 `client.json` 里那个版本的 exe；`-Force` 只用于确认兼容时 |

日志：`logs\tpfake.log` / `connlog.log` / `probe.log` / `pcp.log` / `inject.err.txt`。
`probe.log` 里应能看到 `forcenet: ... (ip 0x0702A8C0)`（`0x0702A8C0` = 10.0.0.7，字节序反过来读）。

## 7. 端口/架构

| 端口 | 谁 | 在哪 |
|---|---|---|
| `:80` ALL.Net / RD2 | 服务器 | 远端 |
| `:52000` SIF 匹配 | 服务器 | 远端 |
| `:52002/udp` spSif ping | 服务器 `udp_echo.py --pong` | 远端 |
| `:4010x` PCP keychip | `pcp_server.py` | **本机 127.0.0.1** |
| 游戏内部 | IC 卡 `C:\iccard.bin` + `C:\iccard.txt` | 本机 |

## 8. 已知限制

- 网络存档（store/nvs）未实现：`status=0` 走本地卡存档，仓库/物品都在 4019B 卡里；
  `status=0x45` 会切到未实现的网络存档并让仓库全禁。详见 `ringedge\A1_CARD_SOURCE.md`。
- PCP 只实现了 `keychip.version`；`keychip.billing.cacertification` + 40107 数据端口未实现，
  计费/使用次数链条不会真正走通（不影响三灯/模式选择）。
- チーム/師弟協力 需要队伍关系，单人环境恒灰。
- 包内不含游戏 exe；请自备同版本。
