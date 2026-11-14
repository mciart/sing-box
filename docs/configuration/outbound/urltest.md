### Structure

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "url": "",
  "interval": "",
  "mode": "auto",
  "tolerance": 50,
  "samples": 5,
  "consecutive": 3,
  "max_failures": 2,
  "idle_timeout": "",
  "interrupt_exist_connections": false
}
```

### Fields

#### outbounds

==Required==

List of outbound tags to test. In `fallback` mode this list is the priority order.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

The probe is one HTTP request over TCP. Its result is shared by TCP, UDP, and ICMP.

#### interval

The test interval. `3m` will be used if empty.

#### mode

`auto` or `fallback`. `auto` is used if empty.

`auto` compares the median of recent successful samples. Another outbound must be faster than the current one by more than `tolerance` for `consecutive` checks before it is selected.

`fallback` keeps the earliest outbound that has not reached `max_failures`. It switches back as soon as an earlier outbound succeeds again, without comparing latency.

#### tolerance

The test tolerance in milliseconds. `50` will be used if empty.

This applies only to successful samples in `auto` mode.

#### samples

Number of recent successful delays kept for each outbound. `5` is used if empty. The median of these delays is the score.

#### consecutive

Number of consecutive checks an outbound must remain sufficiently faster before `auto` switches to it. `3` is used if empty.

#### max_failures

Consecutive probe failures required before an outbound is treated as unavailable. `2` is used if empty. Set it to `1` to switch on the first failed probe. A single slow success or a single failed user connection does not switch.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound changes to a different outbound.

Only inbound connections are affected when this is enabled. Internal connections, such as DNS dialed through the group, are interrupted whenever the selection changes. User traffic is left alone while this remains `false`.
