---
icon: material/new-box
---

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [account_key](#account_key)  
    :material-plus: [key_type](#key_type)  
    :material-plus: [profile](#profile)  
    :material-plus: [http_client](#http_client)

# ACME

!!! quote ""

    `with_acme` build tag required.

### Structure

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
  "http_client": "", // or {}
  "open_firewall": false,
  "open_firewall_only_address": false
}
```

### Fields

#### domain

==Required==

List of domains.

#### data_directory

The directory to store ACME data.

`$XDG_DATA_HOME/certmagic|$HOME/.local/share/certmagic` will be used if empty.

#### default_server_name

Server name to use when choosing a certificate if the ClientHello's ServerName field is empty.

#### email

The email address to use when creating or selecting an existing ACME server account.

#### provider

The ACME CA provider to use.

| Value                   | Provider      |
|-------------------------|---------------|
| `letsencrypt (default)` | Let's Encrypt |
| `zerossl`               | ZeroSSL       |
| `https://...`           | Custom        |

When `provider` is `zerossl`, sing-box will automatically request ZeroSSL EAB credentials if `email` is set and
`external_account` is empty.

When `provider` is `zerossl`, at least one of `external_account`, `email`, or `account_key` is required.

#### account_key

!!! question "Since sing-box 1.14.0"

The PEM-encoded private key of an existing ACME account.

#### disable_http_challenge

Disable all HTTP challenges.

#### disable_tls_alpn_challenge

Disable all TLS-ALPN challenges

#### alternative_http_port

The alternate port to use for the ACME HTTP challenge; if non-empty, this port will be used instead of 80 to spin up a
listener for the HTTP challenge.

#### alternative_tls_port

The alternate port to use for the ACME TLS-ALPN challenge; the system must forward 443 to this port for challenge to
succeed.

#### external_account

EAB (External Account Binding) contains information necessary to bind or map an ACME account to some other account known
by the CA.

External account bindings are used to associate an ACME account with an existing account in a non-ACME system, such as
a CA customer database.

To enable ACME account binding, the CA operating the ACME server needs to provide the ACME client with a MAC key and a
key identifier, using some mechanism outside of ACME. §7.3.4

#### external_account.key_id

The key identifier.

#### external_account.mac_key

The MAC key.

#### dns01_challenge

ACME DNS01 challenge field. If configured, other challenge methods will be disabled.

See [DNS01 Challenge Fields](/configuration/shared/dns01_challenge/) for details.

#### key_type

!!! question "Since sing-box 1.14.0"

The private key type to generate for new certificates.

| Value      | Type    |
|------------|---------|
| `ed25519`  | Ed25519 |
| `p256`     | P-256   |
| `p384`     | P-384   |
| `rsa2048`  | RSA     |
| `rsa4096`  | RSA     |

#### profile

!!! question "Since sing-box 1.14.0"

The ACME profile to use for certificate issuance.

When empty and `provider` is Let's Encrypt, `shortlived` will be used automatically if any domain is an IP address.

#### http_client

!!! question "Since sing-box 1.14.0"

HTTP Client for all provider HTTP requests.

See [HTTP Client Fields](/configuration/shared/http-client/) for details.

#### open_firewall

On Linux, insert an accept rule at the front of every existing `inet`, `ip`, and `ip6` filter input chain while an HTTP-01 challenge is in progress. The rule is sent to the kernel with netlink. `/etc/nftables.conf` is not modified, so a reboot drops the rule. The port is `alternative_http_port`, or 80 when that option is empty. The rule's userdata is `sing-box-acme`. Those rules are deleted when every in-flight challenge has finished (`cert_obtained` or `cert_failed`) and when this provider stops. No table name has to be configured.

The table name does not matter. If no such chain exists, nothing is inserted: mangle, nat, forward, and other hooks do not drop new connections to the local host, and the kernel accepts them by default. A drop in a prerouting chain is left unchanged.

A separate table at priority `filter - 1` is not used. An accept verdict ends only the current chain, so a later input chain with `policy drop` still drops the packet. The accept rule has to live in that chain.

The rule is not inserted for DNS-01 or when `disable_http_challenge` is true. Requires root or `CAP_NET_ADMIN`. A firewall error is logged and does not abort issuance. Reloading a ruleset that flushes the filter table removes the temporary rule. On other operating systems the option has no effect.

#### open_firewall_only_address

Requires `open_firewall`.

When enabled, the accept rule also matches the destination address of the identifier currently being issued, and only when that identifier is an IP address. Other addresses on the same port stay filtered. A domain name has no single destination address, so the port is opened for all destinations and a warning is logged. The HTTP-01 socket still listens on all addresses; packets to other addresses are dropped by the filter chain.
