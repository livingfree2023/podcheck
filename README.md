# podcheck

`podcheck.sh` 是一个面向 Podman 容器的进程特征扫描脚本，用于发现代理、挖矿和测速类软件。检测到匹配进程时，默认会停止对应容器并发送 Telegram 通知。

> 注意：进程特征匹配只能证明相关软件正在运行，不能单独证明存在带宽滥用行为。

## 快速运行

先执行一次不会停止容器的试运行：

```bash
sudo ./podcheck.sh --dry-run
```

确认检测结果后，执行正式扫描：

```bash
sudo ./podcheck.sh
```

正式扫描检测到匹配进程后，会执行 `podman stop -t 2 <容器ID>`。如果只想查看帮助，可以运行：

```bash
./podcheck.sh --help
```

## 安装定时扫描

脚本可以自行安装 systemd service 和 timer：

```bash
sudo ./podcheck.sh --install
```

安装后，脚本会每 3 分钟扫描一次运行中的容器。Telegram 配置文件为 `/etc/podcheck.env`，填写以下变量后即可发送告警：

```ini
TG_TOKEN="你的 Telegram Bot Token"
TG_CHAT_ID="你的 Chat ID"
```

查看服务状态：

```bash
sudo ./podcheck.sh --status
```

## 修改进程匹配列表

脚本顶部的以下三个变量就是进程特征列表。它们不是 Bash 数组，而是使用 `|` 分隔的扩展正则表达式：

```bash
PROXY_KEYWORDS='xrayr|v2bx'
MINING_KEYWORDS='xmrig|minerd|ethminer|cpuminer|stratum'
SPEEDTEST_KEYWORDS='\bspeedtest\b|ookla|openspeedtest|librespeed|\biperf[0-9]*\b|fast\.com'
```

例如，要把 `sing-box` 加入代理软件匹配列表，把配置改为：

```bash
PROXY_KEYWORDS='xrayr|v2bx|sing-box'
```

修改规则时请注意：

- 使用 `|` 表示“或”，不要在两侧添加多余空格。
- 匹配不区分大小写。
- `\b` 表示单词边界，例如 `\bspeedtest\b` 可以减少部分误匹配。
- 修改后建议先使用 `sudo ./podcheck.sh --dry-run` 验证，确认无误后再执行正式扫描。

## 选项

| 选项 | 说明 |
| --- | --- |
| `--dry-run` | 扫描并报告违规进程，但不停止容器 |
| `--verbose` | 输出详细扫描日志 |
| `--install` | 安装 systemd service 和 timer |
| `--uninstall` | 删除 systemd service、timer 和锁文件 |
| `--status` | 查看服务、定时器和最近日志 |
| `--help` | 显示帮助 |

## 运行要求

- Linux
- Podman，路径为 `/usr/bin/podman`
- 运行扫描的用户需要有权限执行 Podman 查询和停止操作；systemd 安装必须使用 root
- 不要为租户容器授予 `CAP_SYS_PTRACE`
