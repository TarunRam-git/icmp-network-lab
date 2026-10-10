# ICMP Network Lab

A local website for Network Failure Detection Using ICMP, by Tarun Ram (24BBS0181). It sends real ICMP requests from the Python backend and displays measured results in a browser.

## Start the website

```bash
git clone https://github.com/TarunRam-git/icmp-network-lab.git
cd icmp-network-lab
./run.sh
```

Open **http://127.0.0.1:8765** in your browser. Python 3 and Linux ICMP socket permission are required. The website uses the Python standard library and plain HTML/CSS/JavaScript, so there is no package installation or build step. Press Ctrl+C in the server terminal to stop it.

## What the website includes

- Single or multiple IPv4 targets, packet count, timeout and TTL controls.
- Real reachability, timeout and ICMP error results, with packet loss and RTT.
- A per-probe RTT chart. Missing replies are not plotted as zero.
- Selectable target rows and the exact outcome of every probe.
- Loopback, documentation-address and TTL demonstration presets. Presets fill inputs; they do not invent results or run automatically.
- Save results as JSON containing the actual observations, collection timestamp and settings.
- Responsive layouts for desktop and mobile.

## A short review demonstration

1. Choose **This computer**, then **Start check**. Explain Echo Request type 8 and Echo Reply type 0, the matched identifiers and successful RTT measurements.
2. Enter `127.0.0.1,192.0.2.1`, use 3 packets and 0.3 seconds timeout, and start a check. Explain the per-target results and aggregate packet loss. The documentation address may time out or produce an error depending on the network.
3. Select the target without replies. Its RTT is unavailable; the graph must not show invented zero values.
4. Choose **Low TTL** and start a check. TTL 1 can elicit a Time Exceeded response from the first router when the route permits it. Explain type 11 and its code.
5. Use the protocol notes below to explain the observed statuses, packet-loss arithmetic and concurrency.
6. Save the actual results for the report.

A timeout does not prove that a device is down. Filtering, packet loss, congestion and routing problems can cause the same observation. ICMP reachability also does not prove that an application or TCP service is healthy.

## How it works

The browser submits targets and settings to `POST /api/check`. The local Python server validates the request and checks up to four targets concurrently. Each probe uses its own Linux ICMP datagram socket, constructs a checksummed Echo Request (type 8, code 0), and waits until its monotonic deadline.

A successful Echo Reply (type 0) must match the sender, identifier, sequence number, payload and checksum. Linux `IP_RECVERR` supplies explicit network errors through the socket error queue, including Destination Unreachable (type 3) and Time Exceeded (type 11). Errors remain separate from successful replies. Local socket or permission failures appear as local errors.

| Observed status | Meaning |
| --- | --- |
| REACHABLE | At least one matching Echo Reply arrived. Individual probes may still be lost. |
| TIMEOUT | No matching reply or explicit error arrived before the deadline. |
| ICMP ERROR | A network device returned an explicit error; inspect the probe type and code. |
| LOCAL ERROR | This computer could not complete the check, for example because of socket permissions. |

Round-trip time is `(reply time - send time) × 1000` milliseconds. Minimum, average and maximum use successful replies only. Packet loss is `(sent requests - matching replies) / sent requests × 100`. If no requests were sent, loss is unavailable. Missing replies have no RTT and are not plotted as zero.

The conceptual Echo Request contains type, code, checksum, identifier, sequence number and a unique payload. TTL is an IPv4 hop limit; a router may return Time Exceeded when it expires. A TTL 1 check can demonstrate this, but its outcome depends on routing and filtering.

## Requirements and limitations

- Python 3 on Linux, a browser, and permission to create ICMP datagram sockets. Raw socket privileges are not required by this implementation.
- IPv4 address literals only; hostnames, multicast, unspecified addresses and limited broadcast are rejected.
- The server binds to `127.0.0.1`; measurements originate from the machine running Python.
- ICMP reachability does not prove that a web application or TCP service is healthy. A timeout alone does not establish that a device is down.
- Results are collected on demand. There is no continuous monitoring, stored history or automatic diagnosis.

If the page is unavailable, check that `./run.sh` is still running and port 8765 is free. For a local permission error, check the machine's Linux ICMP socket policy. Network errors and timeouts can be legitimate measurements; inspect each probe rather than treating them as application failures.

## Files

- `main.py`: checksum, request construction, reply/error matching, socket timing, statistics and concurrent target checking.
- `server.py`: localhost HTTP service and validated JSON check endpoint.
- `web/index.html`: monitoring dashboard structure.
- `web/style.css`: responsive visual design.
- `web/app.js`: requests, state handling, target selection, measured RTT chart and result download.
- `run.sh`: starts the website; accepts `--cli` for terminal demonstrations.
- `test_main.py` and `test_server.py`: isolated engine and HTTP tests.

## Verification commands

```bash
python -m unittest test_main test_server -v
./run.sh --cli --targets 127.0.0.1,1.1.1.1,192.0.2.1 --count 2 --timeout 0.5
./run.sh --cli --targets 1.1.1.1 --count 1 --timeout 1 --ttl 1
```

The website limits each check to 8 targets, 10 probes per target, and 3 seconds timeout; up to 4 targets are checked concurrently. Only one website check runs at a time. Observations remain in browser memory until reload or a new check. There are no accounts, databases or public deployment.

## Protocol references

- [RFC 792](https://www.rfc-editor.org/rfc/rfc792): ICMP message formats.
- [Linux icmp(7)](https://man7.org/linux/man-pages/man7/icmp.7.html): ICMP sockets.
- [Linux ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html): extended error reporting.
