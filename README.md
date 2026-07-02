# snatportchk.sh

Live outbound-connection monitor that shows **DNS hostnames instead of raw IPs** —
without relying on reverse DNS (which is almost never configured for these hosts).

It is an enhanced drop-in for
[`http-deps.sh`](https://raw.githubusercontent.com/karlstal/public-utility-scripts/refs/heads/main/http-deps.sh):
same `netstat` polling loop and same table, but each remote `IP:port` is replaced
with the real `hostname:port` discovered by sniffing TLS handshakes locally.

---

## Install & run (one-liner)

Default (passive first, auto-probe after a 10s grace period):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh
```

Group rows by PID (`--pid`, alias of `-p` / `--group-by-pid`):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh --pid
```

Probe immediately, no grace period (`-a` / `--active`):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh --active
```

Passive only, never self-probe (`--passive` / `--no-probe`):

```bash
curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh && sudo ./snatportchk.sh --passive
```

See [Run](#run) below for what each flag does.

## Run

```bash
sudo ./snatportchk.sh              # sudo/root is required — tcpdump needs raw sockets
sudo ./snatportchk.sh --pid        # (alias: -p / --group-by-pid) group rows by PID, like the original
sudo ./snatportchk.sh --active     # (or -a) enable the active self-probe fallback (off by default)
sudo ./snatportchk.sh --passive    # (or --no-probe) never self-probe; passive collector only (default)
sudo ./snatportchk.sh --verbose    # (or -v) show per-poll diagnostics; default prints just the table
```

**To stop:** press **`q`** (or **Ctrl-C**) — either one shuts down the background
capture, stops tshark/tcpdump, and removes the temp files cleanly.

By default the script is **passive first**: an IP is named from the application's
own TLS handshake if one is seen within `PROBE_DELAY` seconds (default 10). If it
stays unresolved past that window, the script **self-probes** it — opens a
connection and reads the server certificate. Passive names are exact (real SNI);
probe names are approximate (no SNI sent). Use `--active` to probe immediately or
`--passive` to disable probing entirely.

On first run it checks for its tools and, if any are missing, **prompts you to
`apt-get install` them immediately** before continuing.

---

## What it does

Every `POLL_INTERVAL` seconds (default 10s) it prints a table of current
**outbound** TCP connections — excluding *incoming* connections on ports 80/443/2222,
exactly like the original — with these columns:

| Column | Meaning |
|---|---|
| `Remote IP:Port` | The raw remote address and port |
| `DNS` | Resolved hostname, or `-` if not yet known |
| `Service` | Well-known service for the port (e.g. `HTTPS`, `AMQPS`, `MSSQL`, `Redis-TLS`), or `-` if unknown |
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
# tshark captures live itself (no tcpdump|tshark pipe, which can buffer to EOF)
tshark -i any -l -Q -f 'tcp' \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields -e ip.dst -e ipv6.dst -e tls.handshake.extensions_server_name
```

`tshark` captures live on the wire directly. It watches **all TCP** (capture
filter `tcp`, override with `COLLECTOR_CAPFILTER`) and lets its own TLS dissector
pick out **ClientHellos on any port** — HTTPS (443), AMQPS (5671), etc. — rather
than relying on a fragile byte-offset BPF that can silently match nothing on an
`any`/cooked capture. Doing the capture inside `tshark` also avoids the
`tcpdump -w - | tshark -r -` pipe, which on some builds buffers until EOF and so
emits nothing for a live stream. For every ClientHello, `tshark` emits the
destination IP and the **SNI** (`tls.handshake.extensions_server_name`) — the
exact hostname the local application asked for. Each `ip → hostname` pair is
appended to a mappings file
that the main loop folds into the cache on every poll. Because it runs in
parallel, the application's own connections are resolved with zero added latency.

### 2. Active self-probe (automatic fallback after `PROBE_DELAY`, run in parallel)

Long-lived or pre-existing connections never send a *fresh* ClientHello, so the
passive collector can't see them. If an IP stays unresolved for `PROBE_DELAY`
seconds (default 10; `0` = immediate via `--active`; disabled by `--passive`),
the script probes it with a targeted, minimal-duration lookup. **Probes run
concurrently** (up to `MAX_PARALLEL`, default 16), so a poll with a dozen
unresolved hosts finishes in ~1s instead of ~1s × N:

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
> the active probe reads the *server's* certificate (decrypting TLS 1.3 with its
> own logged keys, possibly a default cert). Passive is the reliable engine;
> active is the automatic fallback once an IP outlives the grace period.

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

An IP is only self-probed after it has gone unresolved for `PROBE_DELAY` seconds,
giving the (accurate) passive collector first crack at it.

---

## Requirements & install prompt

| Tool | Package (apt) | Role | Required? |
|---|---|---|---|
| `netstat` | `net-tools` | connection polling | yes |
| `tcpdump` | `tcpdump` | packet capture (needs root) | yes |
| `tshark` | `tshark` | SNI / certificate extraction | yes |
| `openssl` | `openssl` | triggers the handshake for self-probes (3.0+ logs keys to decrypt TLS 1.3; older falls back to TLS 1.2) | soft (falls back to `curl`, then to passive-only) |

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
| `CAPTURE_IFACE` | `any` | Interface passed to `tshark -i` / `tcpdump -i` |
| `COLLECTOR_CAPFILTER` | `tcp` | Capture filter for the passive collector; narrow it on very busy hosts, e.g. `'tcp port 443 or tcp port 5671'` |
| `PROBE_DELAY` | `10` | Seconds an IP may stay unresolved before self-probing (`0` = immediate, same as `--active`) |
| `MAX_PARALLEL` | `16` | Max concurrent self-probes (bounds how many outbound connections we open at once) |
| `TRIGGER_TIMEOUT` | `4` | Max seconds to wait on our own handshake (per probe) |
| `MAX_CAPTURE` | `6` | Hard cap on tcpdump duration per probe |
| `NEG_RETRY_WINDOW` | `300` | Seconds before a failed IP is retried |

Example:

```bash
sudo POLL_INTERVAL=5 CAPTURE_IFACE=eth0 ./snatportchk.sh
```

---

## Limitations

- **Non-TLS traffic can't be named this way.** A hostname is only learnable from a
  TLS handshake (client SNI or server cert). Ports that don't do a readable TLS
  handshake — plain HTTP (80), and often SQL Server (1433, TLS is wrapped inside
  TDS) — keep the raw IP, but the **Service** column still labels them.
- **Capture is now all-port** (a BPF match on the TLS ClientHello), so TLS
  services on non-standard ports — e.g. AMQPS (5671) — resolve passively too, not
  just 443. Volume through the pipe stays small because only ClientHellos match.
  IPv6-only endpoints may be missed (the BPF uses IPv4 offsets).
- **TLS 1.3 encrypts the server certificate.** The self-probe handles this by
  logging its *own* session keys and decrypting with tshark — but only if the
  trigger tool supports key logging (openssl 3.0+ or curl). Without it, the probe
  falls back to forcing TLS 1.2 and can't name TLS 1.3-only servers. (The
  *passive* collector is unaffected either way: the client ClientHello / SNI is
  cleartext in both TLS 1.2 and 1.3.)
- **CDN / shared IPs** may present a wildcard or a different-but-valid cert name
  (e.g. `*.cdn.example.net`) than the app requested. Passive SNI (when available)
  is preferred precisely because it reflects what the app actually asked for; the
  self-probe's cert-derived names are approximate.
- **Self-probing opens a real connection** to the remote IP (and closes it
  immediately) once an IP outlives `PROBE_DELAY`. That is by design; use
  `--passive` to disable it entirely.
- **Live `tcpdump | tshark` pipe:** streams on mainstream builds; if a particular
  `tshark` buffers until EOF, the passive collector may lag — self-probing still
  covers those IPs after the grace period.
