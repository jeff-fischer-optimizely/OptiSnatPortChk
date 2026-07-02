# snatportchk.sh

Live outbound-connection monitor that shows **DNS hostnames instead of raw IPs** —
without relying on reverse DNS (which is almost never configured for these hosts).

It is an enhanced drop-in for
[`http-deps.sh`](https://raw.githubusercontent.com/karlstal/public-utility-scripts/refs/heads/main/http-deps.sh):
same `netstat` polling loop and same table, but each remote `IP:port` is replaced
with the real `hostname:port` discovered by sniffing TLS handshakes locally.

---

## Install & run (one-liner)

Default (passive resolution):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh
```

Group rows by PID (`-p` / `--group-by-pid`):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh -p
```

Also actively probe unseen IPs (`-a` / `--active`):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh --active
```

Both flags together:

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh -p --active
```

See [Run](#run) below for what each flag does.

## Run

```bash
sudo ./snatportchk.sh              # sudo/root is required — tcpdump needs raw sockets
sudo ./snatportchk.sh -p           # (or --group-by-pid) group rows by PID, like the original
sudo ./snatportchk.sh --active     # (or -a) also actively probe IPs the passive collector hasn't seen
```

**To stop:** press **`q`** (or **Ctrl-C**) — either one shuts down the background
capture, stops tshark/tcpdump, and removes the temp files cleanly.

By default the script is **passive**: hostnames come only from the applications'
own TLS handshakes (reliable and accurate). Add `--active` if some IPs stay
unresolved and you want the script to probe them itself — see
**"2. Active on-demand lookup"** below for the trade-offs.

On first run it checks for its tools and, if any are missing, **prompts you to
`apt-get install` them immediately** before continuing.

---

## What it does

Every `POLL_INTERVAL` seconds (default 10s) it prints a table of current
**outbound** TCP connections — excluding *incoming* connections on ports 80/443/2222,
exactly like the original — with these columns:

| Column | Meaning |
|---|---|
| `Remote (DNS or IP):Port` | Hostname if resolved, otherwise the raw IP |
| `PID` | Owning process id |
| `Process` | Owning process name |
| `Total` | Number of matching sockets |
| `States (Count)` | TCP states seen (`ESTABLISHED`, `TIME_WAIT`, …) and their counts |

The only functional change from the original is the first column: raw IPs are
turned into DNS names.

---

## How it resolves IP → DNS (no reverse DNS)

Reverse DNS (`PTR`) is assumed to be unavailable, so the hostname is recovered
directly from the TLS traffic on the wire. Three cooperating pieces do this:

### 1. Async background collector (passive, runs from startup, in parallel)

At launch — before the first poll — a background collector starts so handshakes
are captured from `t=0`:

```bash
tcpdump -i any -nn -U -s0 -w -  'tcp port 443 or tcp port 80' \
  | tshark -r - -l -Q \
      -Y 'tls.handshake.extensions_server_name' \
      -T fields -e ip.dst -e ipv6.dst -e tls.handshake.extensions_server_name
```

`tcpdump` streams the live capture straight into `tshark` (tcpdump writes,
tshark reads — via a pipe). For every TLS **ClientHello**, `tshark` emits the
destination IP and the **SNI** (`tls.handshake.extensions_server_name`) — i.e.
the exact hostname the local application asked for. Each `ip → hostname` pair is
appended to an in-memory-backed mappings file, which the main loop folds into the
cache on every poll. Because it runs in parallel, the application's own
connections are resolved with zero added latency.

### 2. Active on-demand lookup (opt-in — `--active`)

Long-lived or pre-existing connections never send a *fresh* ClientHello, so the
passive collector can't see them. **Only when you pass `--active`**, the script
probes any such IP with a targeted, minimal-duration lookup:

```bash
tcpdump -i any -nn host <IP> and port <PORT> -s0 -w tracedump.pcap        # capture just this host
openssl s_client -keylogfile keys.log -connect <IP>:<PORT> </dev/null     # we open the connection & log OUR keys
tshark -o tls.keylog_file:keys.log -r tracedump.pcap \
       -Y "tls.handshake.extensions_server_name || tls.handshake.type == 11" ...  # decrypt + extract the name
```

It **opens the connection itself** to force a handshake instead of waiting.
Because the script *is* the parent of that `openssl`/`curl` client, it can log
**its own** session keys (`-keylogfile` / the `SSLKEYLOGFILE` env var) and hand
them to tshark via `tls.keylog_file`. tshark then decrypts the handshake — **even
TLS 1.3, where the server certificate is otherwise encrypted** — and reads the
cert. (If key logging isn't available — e.g. openssl older than 3.0 and no curl —
the probe falls back to forcing `-tls1_2`, where the certificate is already
cleartext, and TLS 1.3-only servers won't resolve.)

One subtlety remains, which is why the active result is still *approximate* and
off by default: **no SNI is sent.** Our own ClientHello has no SNI (we don't know
the hostname — that's what we're looking for), so the name comes from the
**server's certificate**, not from what the app requested. On a shared / CDN IP
with SNI-based routing, a no-SNI connection may return a *default* certificate
whose name differs from the one the application actually used.

The extractor reads, in priority order:

1. client SNI (`tls.handshake.extensions_server_name`) — if a real app handshake
   happened to be caught in the window,
2. server-cert SAN (`x509ce.dNSName`),
3. server-cert subject CN (`x509sat.uTF8String` / `printableString`).

`tcpdump` is stopped **as soon as a name is obtained** — it runs only as long as
necessary.

> **Passive vs. active, in one line:** the passive collector reads the *client's*
> SNI (cleartext in TLS 1.2 **and** 1.3, and it's the exact name the app used);
> the active probe reads the *server's* certificate (TLS 1.2 only, and possibly a
> default cert). Passive is the reliable engine; active is a fallback you switch
> on when passive leaves gaps.

### 3. In-memory cache (resolve each IP once)

Results live in a Bash associative array for the life of the process:

- **Positive results are permanent** — an IP is looked up at most once, then
  reused on every subsequent poll (no repeated captures).
- **Failed lookups back off** for `NEG_RETRY_WINDOW` seconds (default 300s) before
  being retried, so dead / non-TLS IPs don't get hammered every cycle.

Status and timing are printed as lookups happen, e.g.:

```
Resolving 6 unique remote host(s): 4 from cache, 2 new lookup(s).
  [async] merged 3 new mapping(s) from background collector.
  [lookup] 93.184.216.34         capturing handshake (port 443)...
  [lookup] 93.184.216.34         -> example.com  (1s)
Resolution pass complete in 2s.
```

---

## Requirements & install prompt

| Tool | Package (apt) | Role | Required? |
|---|---|---|---|
| `netstat` | `net-tools` | connection polling | yes |
| `tcpdump` | `tcpdump` | packet capture (needs root) | yes |
| `tshark` | `tshark` | SNI / certificate extraction | yes |
| `openssl` | `openssl` | triggers the handshake for `--active` lookups (3.0+ logs keys to decrypt TLS 1.3; older falls back to TLS 1.2) | soft (falls back to `curl`, then to passive-only) |

Missing **required** tools trigger an interactive `apt-get install` prompt at
startup (apt only — matching the original script). On non-apt systems you're told
to install them manually.

`tcpdump` needs raw-socket privileges, so run the script with `sudo` / as root.
If you're not root, it automatically prefixes capture commands with `sudo`.

---

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `POLL_INTERVAL` | `10` | Seconds between netstat polls |
| `CAPTURE_IFACE` | `any` | Interface passed to `tcpdump -i` |
| `TRIGGER_TIMEOUT` | `4` | Max seconds to wait on our own handshake (active lookup) |
| `MAX_CAPTURE` | `6` | Hard cap on tcpdump duration per active lookup |
| `NEG_RETRY_WINDOW` | `300` | Seconds before a failed IP is retried |

Example:

```bash
sudo POLL_INTERVAL=5 CAPTURE_IFACE=eth0 ./snatportchk.sh
```

---

## Limitations

- **Non-TLS traffic can't be named this way.** Plain HTTP (port 80) exposes no
  SNI, and a hostname can only be learned from the server certificate on TLS
  ports. Such rows keep the raw IP.
- **TLS 1.3 encrypts the server certificate.** The active probe handles this by
  logging its *own* session keys and decrypting with tshark — but only if the
  trigger tool supports key logging (openssl 3.0+ or curl). Without it, the probe
  falls back to forcing TLS 1.2 and can't name TLS 1.3-only servers. (The
  *passive* collector is unaffected either way: the client ClientHello / SNI is
  cleartext in both TLS 1.2 and 1.3.)
- **CDN / shared IPs** may present a wildcard or a different-but-valid cert name
  (e.g. `*.cdn.example.net`) than the app requested. Passive SNI (when available)
  is preferred precisely because it reflects what the app actually asked for; the
  active probe's cert-derived names are approximate.
- **The active lookup (`--active`) opens a real connection** to the remote IP (and
  closes it immediately). That is by design, to force a handshake without waiting.
- **Live `tcpdump | tshark` pipe:** streams on mainstream builds; if a particular
  `tshark` buffers until EOF, the passive collector may lag — running with
  `--active` still covers those IPs.
