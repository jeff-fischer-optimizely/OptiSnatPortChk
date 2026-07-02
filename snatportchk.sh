#!/bin/bash

# =============================================================================
# snatportchk.sh
#
# Enhanced version of:
#   https://raw.githubusercontent.com/karlstal/public-utility-scripts/refs/heads/main/http-deps.sh
#
# The original polls "netstat -natp" and prints each OUTBOUND remote endpoint as
# a raw IP:port (plus PID, process, and TCP-state counts) every 10 seconds.
#
# This version resolves each remote IP to a real DNS hostname WITHOUT relying on
# reverse DNS (which is almost never configured for these hosts). It does a
# "local lookup" from live TLS traffic instead, via two mechanisms:
#
#   PASSIVE (default) -- an async background collector runs from startup:
#        tcpdump -i any -nn -U -s0 -w -  'tcp port 443 or tcp port 80' \
#          | tshark -r - -T fields -e ip.dst -e tls.handshake.extensions_server_name
#      It reads the CLIENT SNI out of the application's own ClientHello (cleartext
#      in TLS 1.2 AND 1.3), giving the exact hostname the app requested.
#
#   ACTIVE (opt-in, --active) -- for IPs the collector hasn't seen (e.g. long-lived
#      pre-existing connections), open a connection ourselves to force a handshake:
#        tcpdump -i any -nn host <IP> and port <PORT> -s0 -w tracedump.pcap
#      We log OUR OWN session keys (openssl -keylogfile / SSLKEYLOGFILE) so tshark
#      can decrypt even a TLS 1.3 handshake and read the SERVER certificate SAN/CN:
#        tshark -o tls.keylog_file:keys.log -r tracedump.pcap ...
#      No SNI is sent (we don't know the name), so active names are APPROXIMATE.
#
# Results are held in an IN-MEMORY cache (an associative array) so each IP is
# only ever looked up once -- subsequent polls reuse the cached hostname. The
# script reports lookup status and timing as it works, and (in active mode) runs
# tcpdump only as long as needed to obtain the name.
#
# Download & run:
#   curl -s https://raw.githubusercontent.com/jeff-fischer-optimizely/OptiSnatPortChk/main/snatportchk.sh -o snatportchk.sh && chmod +x snatportchk.sh
#   sudo ./snatportchk.sh            # tcpdump needs root/CAP_NET_RAW
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Tunables (override via environment)
# ---------------------------------------------------------------------------
POLL_INTERVAL="${POLL_INTERVAL:-10}"      # seconds between netstat polls
CAPTURE_IFACE="${CAPTURE_IFACE:-any}"     # tcpdump interface
TRIGGER_TIMEOUT="${TRIGGER_TIMEOUT:-4}"   # max seconds to wait on our own handshake
MAX_CAPTURE="${MAX_CAPTURE:-6}"           # hard cap on tcpdump duration per lookup
NEG_RETRY_WINDOW="${NEG_RETRY_WINDOW:-300}" # don't re-attempt a failed IP for this long

# ---------------------------------------------------------------------------
# In-memory lookup tables (persist for the life of the script)
# ---------------------------------------------------------------------------
declare -A NAME_CACHE     # ip -> hostname  (positive results; never re-looked-up)
declare -A LAST_TRY       # ip -> $SECONDS at last FAILED attempt (for retry backoff)

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/snatportchk.XXXXXX")"
MAP_FILE="$WORKDIR/mappings.tsv"   # background collector appends "ip<TAB>hostname" here
: > "$MAP_FILE"
COLLECTOR_PID=""                   # pid of the async tcpdump|tshark collector

# ---------------------------------------------------------------------------
# Root / sudo handling (tcpdump needs raw-socket privileges)
# ---------------------------------------------------------------------------
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    fi
fi

cleanup() {
    trap - EXIT INT TERM          # prevent re-entry while we tear down

    # 1) Reap the collector subshell wrapper.
    [[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null

    # 2) Kill OUR tcpdump captures (root-owned, hence $SUDO). Patterns are scoped
    #    to this script's captures: the collector writes to stdout ('-w -'); each
    #    active lookup writes into $WORKDIR. Once tcpdump dies, the pipe closes and
    #    the collector's tshark ('-r -') and while-loop exit on EOF by themselves.
    $SUDO pkill -f "tcpdump .*-w -"          2>/dev/null   # background collector
    $SUDO pkill -f "tcpdump .*-w ${WORKDIR}" 2>/dev/null   # active per-IP lookups

    # 3) Belt-and-suspenders: if tcpdump was already gone, make sure the
    #    collector's tshark (same user, no sudo needed) isn't left blocked.
    pkill -f "tshark -r -" 2>/dev/null

    rm -rf "$WORKDIR" 2>/dev/null
}
# cleanup runs once, on EXIT. INT/TERM must actually EXIT (a bare trap handler
# would run cleanup but then resume the loop) -- exiting triggers the EXIT trap.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Dependency check + install prompt (apt only, matching the original script)
# ---------------------------------------------------------------------------
apt_install() {
    local pkg="$1"
    echo "  -> installing '$pkg' via apt-get..."
    $SUDO apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "$pkg"
}

require_cmd() {
    # require_cmd <command> <apt-package> <hard|soft>
    local cmd="$1" pkg="$2" severity="${3:-hard}"
    command -v "$cmd" &>/dev/null && return 0

    echo ""
    echo "Required tool '$cmd' is not installed (apt package: $pkg)."
    if ! command -v apt-get &>/dev/null; then
        echo "  apt-get not found on this system -- please install '$pkg' manually."
        [[ "$severity" == "hard" ]] && exit 1
        return 1
    fi

    read -r -p "  Install '$pkg' now? [Y/n] " reply
    reply="${reply:-Y}"
    if [[ "$reply" =~ ^[Yy] ]]; then
        apt_install "$pkg"
        if command -v "$cmd" &>/dev/null; then
            echo "  '$cmd' installed."
            return 0
        fi
        echo "  Installation of '$cmd' failed."
    fi

    if [[ "$severity" == "hard" ]]; then
        echo "  '$cmd' is required -- cannot continue."
        exit 1
    fi
    echo "  Continuing without '$cmd' (some lookups may be less reliable)."
    return 1
}

echo "Checking for required tools..."
require_cmd netstat  net-tools hard      # original dependency
require_cmd tcpdump  tcpdump   hard       # packet capture
require_cmd tshark   tshark    hard       # SNI / certificate extraction

# openssl is used to actively trigger the handshake; curl is a fallback.
# When the trigger tool can log its OWN session keys (SSLKEYLOGFILE convention /
# openssl's -keylogfile), we hand those keys to tshark so it can decrypt the
# TLS 1.3 handshake and read the (otherwise-encrypted) server certificate. If it
# can't, we fall back to forcing TLS 1.2, where the certificate is cleartext.
TRIGGER_TOOL=""
KEYLOG_OK=0
if command -v openssl &>/dev/null; then
    TRIGGER_TOOL="openssl"
    # openssl 3.0+ has 's_client -keylogfile'; 1.1.1 does not.
    if openssl s_client -help 2>&1 | grep -q -- '-keylogfile'; then
        KEYLOG_OK=1
    fi
elif command -v curl &>/dev/null; then
    TRIGGER_TOOL="curl"
    KEYLOG_OK=1        # curl honors the SSLKEYLOGFILE environment variable
else
    require_cmd openssl openssl soft && TRIGGER_TOOL="openssl"
fi
if [[ -z "$TRIGGER_TOOL" ]]; then
    echo "  Note: neither openssl nor curl is available; lookups will rely on"
    echo "        passively catching the application's own handshakes."
fi
echo "Tool check complete."
echo ""

# ---------------------------------------------------------------------------
# Argument parsing (kept from the original)
# ---------------------------------------------------------------------------
GROUP_BY_PID=0
ACTIVE_PROBE=0        # off by default: rely on the passive collector's app-SNI
for arg in "$@"; do
    case "$arg" in
        --group-by-pid|-p) GROUP_BY_PID=1 ;;
        # Opt-in active probing: open the connection ourselves to name IPs the
        # passive collector hasn't seen. We log our own session keys so tshark
        # can decrypt even a TLS 1.3 handshake and read the server certificate.
        # Approximate (no SNI sent) -- see the note printed at startup.
        --active|-a)       ACTIVE_PROBE=1 ;;
    esac
done

# ---------------------------------------------------------------------------
# trigger_handshake <ip> <port> <keylog>
#   Actively open (and immediately close) a TLS connection to force the server
#   to present its certificate, so the capture contains a full handshake.
#   We control this client, so we log ITS session keys to <keylog> (via
#   -keylogfile / SSLKEYLOGFILE). tshark can then decrypt the handshake -- even
#   TLS 1.3, where the certificate is encrypted -- and read the cert SAN/CN.
#   If key logging isn't available, we instead cap at TLS 1.2, where the
#   certificate is already cleartext. Only reached when --active is set.
# ---------------------------------------------------------------------------
trigger_handshake() {
    local ip="$1" port="$2" keylog="$3"
    case "$TRIGGER_TOOL" in
        openssl)
            # No -servername: we don't know the host. The server answers with
            # its default certificate, whose SAN/CN gives us the hostname.
            if [[ "$KEYLOG_OK" -eq 1 ]]; then
                timeout "$TRIGGER_TIMEOUT" openssl s_client -keylogfile "$keylog" \
                    -connect "${ip}:${port}" </dev/null >/dev/null 2>&1
            else
                timeout "$TRIGGER_TIMEOUT" openssl s_client -tls1_2 \
                    -connect "${ip}:${port}" </dev/null >/dev/null 2>&1
            fi
            ;;
        curl)
            if [[ "$KEYLOG_OK" -eq 1 ]]; then
                SSLKEYLOGFILE="$keylog" timeout "$TRIGGER_TIMEOUT" curl -sk \
                    --max-time "$TRIGGER_TIMEOUT" "https://${ip}:${port}/" \
                    -o /dev/null 2>/dev/null
            else
                timeout "$TRIGGER_TIMEOUT" curl -sk --tlsv1.2 --tls-max 1.2 \
                    --max-time "$TRIGGER_TIMEOUT" "https://${ip}:${port}/" \
                    -o /dev/null 2>/dev/null
            fi
            ;;
        *)
            # No trigger tool: just wait briefly for organic traffic.
            sleep 1
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# extract_name <pcap> [keylog]
#   Pull a hostname from the captured handshake. Preference order:
#     1. client SNI (tls.handshake.extensions_server_name) -- present if the
#        real application handshook during the capture window.
#     2. server certificate SAN dNSName (x509ce.dNSName)
#     3. server certificate subject CN  (x509sat.uTF8String / printableString)
#   If <keylog> is a non-empty key-log file, it is passed to tshark
#   (tls.keylog_file) so an encrypted TLS 1.3 handshake can be decrypted and its
#   certificate read.
# ---------------------------------------------------------------------------
extract_name() {
    local pcap="$1" keylog="${2:-}" sni sans cn1 cn2 cand name=""
    local keyopt=()
    [[ -n "$keylog" && -s "$keylog" ]] && keyopt=(-o "tls.keylog_file:$keylog")
    while IFS=$'\t' read -r sni sans cn1 cn2; do
        for cand in "$sni" "$sans" "$cn1" "$cn2"; do
            cand="${cand%%,*}"          # first entry of a comma-separated list
            cand="${cand// /}"          # strip stray spaces
            if [[ -n "$cand" && "$cand" != *$'\x00'* ]]; then
                name="$cand"
                break
            fi
        done
        [[ -n "$name" ]] && break
    done < <(
        tshark -r "$pcap" "${keyopt[@]}" \
            -Y 'tls.handshake.extensions_server_name || tls.handshake.type == 11' \
            -T fields \
            -e tls.handshake.extensions_server_name \
            -e x509ce.dNSName \
            -e x509sat.uTF8String \
            -e x509sat.printableString \
            2>/dev/null
    )
    printf '%s' "$name"
}

# ---------------------------------------------------------------------------
# start_collector
#   Launch the ASYNC background collector: tcpdump streams the live capture
#   straight into tshark (tcpdump writes, tshark reads -- via a pipe), which
#   emits "ip.dst<TAB>hostname" for every TLS ClientHello it sees on 80/443.
#   Each observed mapping is appended to $MAP_FILE. This runs in parallel from
#   startup, so the application's own handshakes are harvested immediately and
#   the main loop rarely has to block on an on-demand lookup.
# ---------------------------------------------------------------------------
start_collector() {
    (
        $SUDO tcpdump -i "$CAPTURE_IFACE" -nn -U -s0 -w - \
            'tcp port 443 or tcp port 80' 2>/dev/null \
        | tshark -r - -l -Q \
            -Y 'tls.handshake.extensions_server_name' \
            -T fields -e ip.dst -e ipv6.dst \
            -e tls.handshake.extensions_server_name 2>/dev/null \
        | while IFS=$'\t' read -r ip4 ip6 sni; do
              ip="${ip4:-$ip6}"
              sni="${sni%%,*}"
              [[ -n "$ip" && -n "$sni" ]] && printf '%s\t%s\n' "$ip" "$sni" >> "$MAP_FILE"
          done
    ) &
    COLLECTOR_PID=$!
}

# ---------------------------------------------------------------------------
# merge_collector
#   Fold any hostnames the async collector has discovered into the in-memory
#   cache. Cheap (small file, cache dedups), so it runs every poll.
# ---------------------------------------------------------------------------
merge_collector() {
    [[ -s "$MAP_FILE" ]] || return 0
    local ip name added=0
    while IFS=$'\t' read -r ip name; do
        [[ -n "$ip" && -n "$name" ]] || continue
        if [[ -z "${NAME_CACHE[$ip]+x}" ]]; then
            NAME_CACHE[$ip]="$name"
            unset 'LAST_TRY[$ip]'
            added=$((added+1))
        fi
    done < "$MAP_FILE"
    (( added > 0 )) && echo "  [async] merged ${added} new mapping(s) from background collector."
    return 0
}

# ---------------------------------------------------------------------------
# lookup_ip <ip> <port>
#   Returns the hostname on stdout (empty if unresolved). Uses/updates the
#   in-memory cache and prints status + timing to stderr so it doesn't pollute
#   the returned value.
# ---------------------------------------------------------------------------
lookup_ip() {
    local ip="$1" port="$2"

    # 1) Positive cache hit -- never look up twice.
    if [[ -n "${NAME_CACHE[$ip]+x}" ]]; then
        printf '%s' "${NAME_CACHE[$ip]}"
        return 0
    fi

    # 2) Passive-only mode (default): no active probe. The IP stays unresolved
    #    until the background collector sees the app's own handshake for it.
    if [[ "$ACTIVE_PROBE" -ne 1 ]]; then
        printf ''
        return 0
    fi

    # 3) Recent failure -- back off instead of hammering the same dead IP.
    if [[ -n "${LAST_TRY[$ip]+x}" ]]; then
        local age=$(( SECONDS - LAST_TRY[$ip] ))
        if (( age < NEG_RETRY_WINDOW )); then
            printf ''
            return 0
        fi
    fi

    # 4) Active probe (--active): run tcpdump only as long as necessary.
    local pcap="$WORKDIR/lookup.pcap" keylog="$WORKDIR/lookup.keys" start elapsed name
    start=$SECONDS
    printf '  [lookup] %-21s capturing handshake (port %s)...\n' "$ip" "$port" >&2

    rm -f "$pcap"; : > "$keylog"
    $SUDO timeout "$MAX_CAPTURE" tcpdump -i "$CAPTURE_IFACE" -nn \
        "host $ip and port $port" -s0 -w "$pcap" >/dev/null 2>&1 &
    local cap_pid=$!

    sleep 0.3                     # let tcpdump bind before we generate traffic
    trigger_handshake "$ip" "$port" "$keylog"   # logs our own session keys
    sleep 0.4                     # allow final handshake packets to be written

    # Stop the capture as soon as we have what we need.
    $SUDO kill "$cap_pid" 2>/dev/null
    wait "$cap_pid" 2>/dev/null

    name=""
    # Our own session keys let tshark decrypt the handshake (incl. TLS 1.3) and
    # read the server certificate.
    [[ -s "$pcap" ]] && name="$(extract_name "$pcap" "$keylog")"
    elapsed=$(( SECONDS - start ))

    if [[ -n "$name" ]]; then
        NAME_CACHE[$ip]="$name"
        unset 'LAST_TRY[$ip]'
        printf '  [lookup] %-21s -> %s  (%ss)\n' "$ip" "$name" "$elapsed" >&2
        printf '%s' "$name"
    else
        LAST_TRY[$ip]=$SECONDS
        printf '  [lookup] %-21s -> (no DNS found)  (%ss)\n' "$ip" "$elapsed" >&2
        printf ''
    fi
}

# ---------------------------------------------------------------------------
# wait_or_quit <seconds>
#   Wait up to <seconds> between polls, but return non-zero the moment the user
#   presses 'q' (clean stop). Only interactive when stdin is a real terminal;
#   otherwise (piped / non-interactive) it just sleeps. Pressing any other key
#   returns immediately to refresh early. Ctrl-C still works in either case.
# ---------------------------------------------------------------------------
wait_or_quit() {
    local secs="$1" key
    if [[ -t 0 ]]; then
        if read -rsN1 -t "$secs" key 2>/dev/null; then
            [[ "$key" == "q" || "$key" == "Q" ]] && return 1
        fi
        return 0
    fi
    sleep "$secs"
    return 0
}

# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------
echo "Enhanced connection monitor with local DNS resolution."
echo "  * Reverse DNS is NOT used; hostnames come from live TLS handshakes."
echo "  * Each remote IP is resolved once via tcpdump+tshark, then cached in memory."
echo "  * tcpdump requires root; running via: ${SUDO:-<already root>}"
echo "  * Press 'q' or Ctrl-C at any time to stop cleanly."
if [[ "$ACTIVE_PROBE" -eq 1 ]]; then
    echo "  * ACTIVE probing ENABLED (--active): unseen IPs are probed by opening a"
    echo "    connection and reading the server cert. Names so obtained are"
    echo "    APPROXIMATE (no SNI sent)."
    if [[ "$KEYLOG_OK" -eq 1 ]]; then
        echo "    TLS 1.3 supported: our own session keys are logged so tshark can"
        echo "    decrypt the handshake and read the certificate."
    else
        echo "    Key logging unavailable (need openssl 3.0+ or curl); falling back"
        echo "    to forcing TLS 1.2, so TLS 1.3-only servers won't resolve."
    fi
else
    echo "  * Passive mode: names come only from the app's own handshakes."
    echo "    Re-run with --active to also probe IPs the collector hasn't seen."
fi
echo ""

# Kick off the async collector NOW so handshakes are harvested from t=0,
# in parallel with the polling loop below.
start_collector
echo "Background collector started (pid ${COLLECTOR_PID}); harvesting SNIs in parallel."
echo ""

while true; do
    echo "Polling current connections (excluding INBOUND on 80/443/2222)..."
    echo ""

    # Fold anything the async collector has already discovered into the cache.
    merge_collector

    # --- Snapshot netstat into tab-separated rows: remote \t pid \t prog \t total \t states
    mapfile -t ROWS < <(
        netstat -natp 2>/dev/null | awk -v group_by_pid="$GROUP_BY_PID" '
        /ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT/ {
            split($4, laddr, ":");
            localPort = (length(laddr) > 2 ? laddr[length(laddr)] : laddr[2]);
            foreignAddr = $5;
            state = $6;

            split($7, pidprog, "/");
            pid = pidprog[1];
            prog = pidprog[2];
            if (pid == "" || pid == "-") pid = "N/A";
            if (prog == "" || prog == "-") prog = "kernel";

            if (localPort !~ /^(80|443|2222)$/) {
                key = foreignAddr;
                if (group_by_pid == 1) key = key " " pid " " prog;
                else                   key = key " " prog;
                state_counts[key " " state]++;
                total_counts[key]++;
                pid_map[key]  = pid;
                prog_map[key] = prog;
            }
        }
        END {
            for (k in total_counts) {
                split(k, parts, " ");
                remote = parts[1];
                if (group_by_pid == 1) { pid = parts[2]; prog = parts[3]; }
                else                   { pid = pid_map[k]; prog = prog_map[k]; }

                slen = 0; delete state_list_arr;
                for (s in state_counts) {
                    if (s ~ "^" k " ") {
                        split(s, segs, " ");
                        st = segs[length(segs)];
                        state_list_arr[slen++] = st "(" state_counts[s] ")";
                    }
                }
                state_list = state_list_arr[0];
                for (i = 1; i < slen; i++) state_list = state_list " " state_list_arr[i];

                printf "%s\t%s\t%s\t%d\t%s\n", remote, pid, prog, total_counts[k], state_list;
            }
        }' | sort -t$'\t' -k4,4nr
    )

    # --- Resolve pass: figure out which IPs are new vs already cached.
    declare -A SEEN_THIS_POLL=()
    new_count=0; cached_count=0
    for row in "${ROWS[@]}"; do
        remote="${row%%$'\t'*}"          # IP:port
        ip="${remote%:*}"
        [[ -n "${SEEN_THIS_POLL[$ip]+x}" ]] && continue
        SEEN_THIS_POLL[$ip]=1
        if [[ -n "${NAME_CACHE[$ip]+x}" ]]; then
            cached_count=$((cached_count+1))
        else
            new_count=$((new_count+1))
        fi
    done

    total_unique=${#SEEN_THIS_POLL[@]}
    echo "Resolving ${total_unique} unique remote host(s): ${cached_count} from cache, ${new_count} new lookup(s)."
    resolve_start=$SECONDS

    # Perform the actual lookups (status/timing printed by lookup_ip to stderr).
    declare -A SEEN_LOOKUP=()
    for row in "${ROWS[@]}"; do
        remote="${row%%$'\t'*}"
        ip="${remote%:*}"; port="${remote##*:}"
        [[ -n "${SEEN_LOOKUP[$ip]+x}" ]] && continue
        SEEN_LOOKUP[$ip]=1
        lookup_ip "$ip" "$port" >/dev/null
    done
    resolve_elapsed=$(( SECONDS - resolve_start ))
    echo "Resolution pass complete in ${resolve_elapsed}s."
    echo ""

    # --- Render the enriched table (hostname substituted for IP where known).
    printf "%-52s %-8s %-20s %-8s %s\n" "Remote (DNS or IP):Port" "PID" "Process" "Total" "States (Count)"
    printf '%.0s-' {1..110}; echo

    unresolved=0
    for row in "${ROWS[@]}"; do
        IFS=$'\t' read -r remote pid prog total states <<< "$row"
        ip="${remote%:*}"; port="${remote##*:}"
        name="${NAME_CACHE[$ip]:-}"
        if [[ -n "$name" ]]; then
            display="${name}:${port}"
        else
            display="$remote"
            unresolved=$((unresolved+1))
        fi
        printf "%-52s %-8s %-20s %-8s %s\n" "$display" "$pid" "$prog" "$total" "$states"
    done

    printf '%.0s-' {1..110}; echo
    if (( unresolved > 0 )); then
        echo "Note: ${unresolved} row(s) still show a raw IP -- no TLS name was obtained"
        echo "      (non-TLS port, handshake not captured, or server sent no usable cert)."
        echo "      These are retried automatically after ${NEG_RETRY_WINDOW}s."
    fi
    echo "Cache now holds ${#NAME_CACHE[@]} IP->DNS mapping(s)."
    echo "Press 'q' or Ctrl-C to quit; refreshing in ${POLL_INTERVAL}s..."
    echo ""
    if ! wait_or_quit "$POLL_INTERVAL"; then
        echo "Stopping at your request -- shutting down capture and cleaning up..."
        break
    fi
done
# Falling off the loop (via 'q') runs the EXIT trap -> cleanup(), same as Ctrl-C.
