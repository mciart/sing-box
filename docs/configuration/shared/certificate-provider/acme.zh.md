---
icon: material/new-box
---

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [account_key](#account_key)  
    :material-plus: [key_type](#key_type)  
    :material-plus: [profile](#profile)  
    :material-plus: [http_client](#http_client)

# ACME

!!! quote ""

    需要 `with_acme` 构建标签。

### 结构

```json
{
  "type": "acme",
  "tag": "",

  "domain": [],
  "data_directory": "",
  "default_server_name": "",
  "email": "",
  "provider": "",
  "account_key": "",
  "disable_http_challenge": false,
  "disable_tls_alpn_challenge": false,
  "alternative_http_port": 0,
  "alternative_tls_port": 0,
  "external_account": {
    "key_id": "",
    "mac_key": ""
  },
  "dns01_challenge": {},
  "key_type": "",
  "profile": "",
  "http_client": "", // 或 {}
  "open_firewall": false,
  "open_firewall_only_address": false
}
```

### 字段

#### domain

==必填==

域名列表。

#### data_directory

ACME 数据存储目录。

如果为空则使用 `$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic`。

#### default_server_name

如果 ClientHello 的 ServerName 字段为空，则选择证书时要使用的服务器名称。

#### email

创建或选择现有 ACME 服务器帐户时使用的电子邮件地址。

#### provider

要使用的 ACME CA 提供商。

| 值                  | 提供商           |
|--------------------|---------------|
| `letsencrypt (默认)` | Let's Encrypt |
| `zerossl`          | ZeroSSL       |
| `https://...`      | 自定义           |

当 `provider` 为 `zerossl` 时，如果设置了 `email` 且未设置 `external_account`，
sing-box 会自动向 ZeroSSL 请求 EAB 凭据。

当 `provider` 为 `zerossl` 时，必须至少设置 `external_account`、`email` 或 `account_key` 之一。

#### account_key

!!! question "自 sing-box 1.14.0 起"

现有 ACME 帐户的 PEM 编码私钥。

#### disable_http_challenge

禁用所有 HTTP 质询。

#### disable_tls_alpn_challenge

禁用所有 TLS-ALPN 质询。

#### alternative_http_port

用于 ACME HTTP 质询的备用端口；如果非空，将使用此端口而不是 80 来启动 HTTP 质询的侦听器。

#### alternative_tls_port

用于 ACME TLS-ALPN 质询的备用端口； 系统必须将 443 转发到此端口以使质询成功。

#### external_account

EAB（外部帐户绑定）包含将 ACME 帐户绑定或映射到 CA 已知的其他帐户所需的信息。

外部帐户绑定用于将 ACME 帐户与非 ACME 系统中的现有帐户相关联，例如 CA 客户数据库。

为了启用 ACME 帐户绑定，运行 ACME 服务器的 CA 需要使用 ACME 之外的某种机制向 ACME 客户端提供 MAC 密钥和密钥标识符。§7.3.4

#### external_account.key_id

密钥标识符。

#### external_account.mac_key

MAC 密钥。

#### dns01_challenge

ACME DNS01 质询字段。如果配置，将禁用其他质询方法。

参阅 [DNS01 质询字段](/zh/configuration/shared/dns01_challenge/)。

#### key_type

!!! question "自 sing-box 1.14.0 起"

为新证书生成的私钥类型。

| 值         | 类型      |
|-----------|----------|
| `ed25519` | Ed25519 |
| `p256`    | P-256   |
| `p384`    | P-384   |
| `rsa2048` | RSA     |
| `rsa4096` | RSA     |

#### profile

!!! question "自 sing-box 1.14.0 起"

用于证书签发的 ACME profile。

当为空且 `provider` 为 Let's Encrypt 时，如果任意域名为 IP 地址，将自动使用 `shortlived`。

#### http_client

!!! question "自 sing-box 1.14.0 起"

用于所有提供者 HTTP 请求的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

#### open_firewall

在 Linux 上，HTTP-01 质询进行期间，向已有的 `inet`、`ip`、`ip6` filter input 链最前面插入 accept 规则。规则通过 netlink 写入内核，不修改 `/etc/nftables.conf`，重启后规则消失。端口为 `alternative_http_port`，未设置时为 80。规则 userdata 为 `sing-box-acme`。全部进行中的质询结束（`cert_obtained` 或 `cert_failed`）以及该提供者停止时删除这些规则。不需要在配置里指定表名。

表名不限。没有这类链时不插规则：mangle、nat、forward 和其他钩子不丢发往本机的新连接，内核默认放行。prerouting 上的 drop 不会被改动。

不再使用优先级 `filter - 1` 的独立表。`accept` 只结束当前链，后面 `policy drop` 的 input 链仍会丢包，所以放行规则必须写进那条链。

使用 DNS-01 或 `disable_http_challenge` 为 true 时不会插入。需要 root 或 `CAP_NET_ADMIN`。防火墙操作失败只记录日志，不会中断证书申请。重载会清空 filter 表的规则集时，临时规则也会被清掉。其他操作系统上此选项无效。

#### open_firewall_only_address

需要同时打开 `open_firewall`。

启用后，HTTP-01 只监听正在签发的 IP 和端口，`ss` 里看到的是这个地址而不是 `*:80`。防火墙规则也同样只放行这个目的地址。同一个 provider 的其他地址会等这次质询结束后再监听。域名没有唯一地址，这时仍监听所有地址并记录一条警告。
