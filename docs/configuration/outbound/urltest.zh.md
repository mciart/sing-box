### 结构

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

### 字段

#### outbounds

==必填==

用于测试的出站标签列表。`fallback` 模式下，这个顺序就是优先级。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

探测是一次走 TCP 的 HTTP 请求。TCP、UDP 和 ICMP 共用这次结果。

#### interval

测试间隔。默认使用 `3m`。

#### mode

`auto` 或 `fallback`。留空时使用 `auto`。

`auto` 比较最近成功样本的中位数。另一个出口必须比当前出口快过 `tolerance`，并且连续 `consecutive` 次成立，才会被选中。

`fallback` 使用还没有达到 `max_failures` 的最靠前出口。更靠前的出口一旦重新探测成功，就切回去，不比较延迟。

#### tolerance

以毫秒为单位的测试容差。默认使用 `50`。

只用于 `auto` 模式里的成功样本。

#### samples

每个出口保留的最近成功延迟次数。留空时使用 `5`。分数是这些延迟的中位数。

#### consecutive

`auto` 切换前，另一个出口需要连续更快的探测次数。留空时使用 `3`。

#### max_failures

连续探测失败多少次后，把出口视为不可用。留空时使用 `2`。设为 `1` 时，第一次探测失败就切换。单次变慢或单次用户连接失败不会切换。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### interrupt_exist_connections

选定的出站真正换成另一个出口时，是否中断现有连接。

启用后会影响入站连接。组自己拨出的内部连接，例如经过这个组的 DNS，在选择变化时总会中断。此项保持 `false` 时，用户正在使用的连接不会被断开。