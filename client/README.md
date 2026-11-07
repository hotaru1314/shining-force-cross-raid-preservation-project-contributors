# client —— 机台侧客户端包（配合 server2.0 使用）

> 这是跑在**机台那台 Windows** 上的部分：启动器 + 注入用的辅助 DLL + 卡片/PCP 配置。
> 协议与本仓库 [`../spec.md`](../spec.md) 对应，服务端见 [`../server2.0/`](../server2.0/)。

---

## 1. 它做什么

1. 读 `client.json`，生成 `cfg\dnsmap.txt`（把机台要访问的域名指到你的服务器）；
2. 启动一个**本机 PCP**（假钥匙芯片），游戏起来时由它应答；
3. 用 `bin\inject_multi.exe` 把 `bin\*.dll` 注入游戏进程，替换掉真实的 JVS / 读卡器 / 钥匙芯片；
4. 启动游戏本体。

## 2. 前置条件

- 你**自己**拥有游戏本体（本仓库不含任何游戏文件、ROM、卡镜像）；
- 把 `client.json` 的 `game_dir` 指到你的安装目录；
- `exe_sha256` 是那份 exe 的校验值 —— 对不上说明版本不同，启动器会拒绝（确认无碍可加 `--force`）；
- 机台（或测试机）与服务器在**同一个内网**，`server2.0/config.json` 的 `server_ip` 指向服务器网卡 IP。

## 3. 快速开始

```powershell
# 1) 改 client.json：server_ip / game_dir / pcp.networkaddr / pcp.keyid
# 2) 以管理员身份运行（注入需要权限）
launch_client.bat
```

启动器会依次做：生成 dnsmap → 起本机 PCP → 结束旧游戏进程 → 注入 → 启动游戏。
日志都在 `logs\`（`inject.out.txt` 能看到注入了哪几个 DLL）。

## 4. 目录

```
client/
├── client.json           唯一配置：服务器 IP、游戏目录、keychip、卡片字段
├── launch_client.bat     Windows 下的入口（管理员运行）
├── launch_client.ps1     PowerShell 版（逻辑完整，含注入）
├── launch_client.py      同上的 Python 版
├── setup_card.bat/.ps1   准备一张"文件型"空卡（本仓库不含卡镜像）
├── udp3953.py            客户端侧的对局抓包/观察小工具
├── CLIENT.md             更细的客户端说明（历史记录）
├── bin/                  注入用的辅助 DLL（见 §5）
├── cfg/                  dnsmap / poke.cfg（内存补丁表）/ comfake.txt
├── card/                 卡片相关（只放 IC 卡的文本 ID；镜像需自备）
└── pcp/                  本机假 PCP（钥匙芯片应答）
```

## 5. 关于 `bin/` 里的 DLL

`bin\` 是**预编译的辅助 DLL**，用途都在名字里：

| DLL | 作用 |
|---|---|
| `tpfake.dll` | 替代 TeknoParrot 的那部分补丁（JVS / 读卡器 / 网络） |
| `probe_focus.dll` | 输入焦点修复 + 一些运行时补丁 |
| `windower.dll` | 让游戏跑在 1296×759 窗口里，不切分辨率 |
| `serialfake.dll` | 假串口（读卡器） |
| `touchfake.dll` | 鼠标 → 触摸 |
| 其它 `*dump.dll` / `*log.dll` | 抓包与日志（调试用，默认不注入） |

> **源码不在本仓库**。它们是为这个游戏逆向出来的辅助工具，二进制随包提供以便复现；
> 需要改的话得自己反汇编。**不含任何 SEGA 的代码或资源。**

## 6. 合规

- 不含游戏本体、ROM、美术/音频、卡镜像；
- `cfg\poke.cfg` 是**内存补丁地址表**（针对特定 exe 版本），属于逆向数据；
- `client.json` 里的 IP、keychip、卡片字段全部是**示例值**；
- 用途是**已停运街机的保存与研究**，请自行确认所在地区的合法性。
