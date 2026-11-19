# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## 与原版 sing-box 的差异

这一支基于 v1.14.4。运行时和原版不同的地方有协议嗅探、urltest 选择、ACME 申请时临时放行 HTTP-01 端口，以及发布时用的编译流程。

### 协议嗅探

新增两个 TCP 探测器，都看连接的第一段数据，不看端口。

- `minecraft`：Minecraft Java 握手。包号是 `0x00`，下一状态是 `1`、`2` 或 `3`。握手里的服务器地址记成域名；Forge 附加数据只保留 `\0` 前面的主机名。
- `terraria`：泰拉瑞亚连接请求。小端长度、包号 `1`，版本字符串是 `Terraria` 加数字，例如 `Terraria279`。这个字符串记到客户端字段。

没有写 `sniffer` 列表时，默认嗅探包含这两个。单独指定时要写上名字，例如 `"sniffer": ["minecraft", "terraria"]`。路由可以用 `"protocol": "minecraft"` 或 `"protocol": "terraria"`。

### urltest

TCP、UDP 和 ICMP 共用同一次选择，只保留一个 `selected`。探测仍然是一条 HTTP 请求，不为 UDP 再测一次。结果按出站名字存一条，不再分成 TCP 和 UDP 两份。

`mode` 为 `auto` 或 `fallback`，默认 `auto`。

- `auto` 比较的是最近成功样本的中位数。另一个出口必须快过 `tolerance`，并且连续 `consecutive` 次都成立，才切换。
- `fallback` 按 `outbounds` 的顺序当优先级，不比较快慢。前面的还没被判失败就继续用前面的；它恢复后，下一轮探测成功就切回去。

每个出口保留最近 `samples` 次成功延迟，默认 `5` 次。一次变慢只增加一个成功样本，不换出口。

连不上、超时、重置单独计数。连续失败要达到 `max_failures`，默认 `2` 次，才删掉可用记录并换出口。设为 `1` 时，第一次探测失败就切换。单次用户连接失败不会清掉记录，也不会因此换出口。

`interrupt_exist_connections` 默认仍是 `false`。只有 `selected` 真正换成另一个出口时，才打断这个组自己拨出去的内部连接，例如 DNS。用户正在看的视频保持不断。

```json
{
  "type": "urltest",
  "tag": "urltest",
  "outbounds": ["de", "us"],
  "url": "https://cp.cloudflare.com/generate_204",
  "interval": "10s",
  "mode": "auto",
  "tolerance": 100,
  "samples": 5,
  "consecutive": 3,
  "max_failures": 2,
  "interrupt_exist_connections": false
}
```

`fallback` 把顺序写成优先级即可，例如 `"outbounds": ["de", "us"]`、`"mode": "fallback"`。

### ACME 防火墙

ACME certificate provider 增加 `open_firewall`。为 `true` 时，HTTP-01 质询开始后，在已有的 `inet`、`ip`、`ip6` filter input 链最前面插入 `tcp dport 80 accept`。端口跟着 `alternative_http_port`，没写就是 80。规则的 userdata 是 `sing-box-acme`。质询成功、失败，或这个 provider 停止时，只删这些规则。

规则通过 netlink 写进内核，不改 `/etc/nftables.conf`。断电重启后内核规则清空，端口回到配置文件里的状态。sing-box 崩溃而机器没重启时，规则会留到下次启动，启动时会先清掉带这个 userdata 的规则。不需要配置表名。

`open_firewall_only_address` 为 true 时，规则再匹配正在签发的 IP，例如 `tcp dport 80 ip daddr 203.0.113.5 accept`。其他地址的 80 仍然被 filter 丢掉。标识符是域名时没有唯一目的地址，退回放行所有地址并记一条警告。HTTP 套接字仍监听所有地址。

链的表名不限。没有 filter input 链时不插规则：mangle、nat、forward 或其他钩子不挡发往本机的新连接，内核默认放行。有 filter input 时，规则插在该链最前面，能压住这条链后面的 drop 和 `policy drop`。prerouting 上的 drop 不在这里处理。

不能靠另建一张优先级 `filter - 1` 的表。`accept` 只结束当前链，包还会继续进入后面的链。`policy drop` 的 filter input 优先级是 0，更早的 accept 挡不住它。

DNS-01，或 `disable_http_challenge` 为 true 时，不插规则。需要 root 或 `CAP_NET_ADMIN`。插规则失败只记日志，证书申请继续。质询过程中执行 `nft -f /etc/nftables.conf` 会 `flush table inet filter`，临时规则会被清掉。

### 发布

版本号使用 `v1.14.4-mciart-N`。`N` 从 0 开始，每发布一次加 1。开发分支固定叫 `v1.14.4-mciart`，不跟随这个序号改名。

`v1.14.4-mciart` 由 `v1.14.4-game` 改名而来，并且是本仓库的默认分支。

- `v1.14.4-mciart-0`：Minecraft 与泰拉瑞亚探测。
- `v1.14.4-mciart-1`：在上一版上加入 TCP、UDP、ICMP 共用一次选择的 urltest。
- `v1.14.4-mciart-2`：申请 ACME 证书时，在已有的 filter input 链临时放行 HTTP-01 端口。

打上 `v*` 标签后，`.github/workflows/release.yml` 交叉编译 sing-box 本体并发布到 GitHub Releases。编译标签使用 `release/DEFAULT_BUILD_TAGS_OTHERS`，关闭 CGO，不包含 naive outbound。程序里的版本号取自标签名。

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```