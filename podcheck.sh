#!/bin/bash
#
# podcheck.sh — Prohibited / suspicious process signature scanner for Podman.
#
# This is NOT a bandwidth-abuse detector. It is a process-signature scanner:
# finding a match proves the named software is running inside a container, not
# that bandwidth is being abused.  Network-usage evidence is a separate signal
# to be added later.
#
# Operational requirement: tenant containers must NOT be granted CAP_SYS_PTRACE.
# The host uses `podman top` (host-side) to inspect container processes, which
# does not require SYS_PTRACE inside the container.  Granting it would widen the
# attack surface without any monitoring benefit.
#
# Designed to run as a short-lived systemd oneshot service invoked by the timer.
# This file is self-installing: run "podcheck.sh --install" as root to deploy
# the service/timer units (generated from templates embedded below) and enable
# the timer, making this single file the only artifact to ship.

set -u

# ==============================================================================
# 0. Configuration
# ==============================================================================

# --- Telegram notification credentials ----------------------------------------
# Provide via environment or edit here. Never hardcode in version control.
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

# --- Suspicious-software signatures (tripwire only) ----------------------------
# These match process command names/arguments inside containers. They are
# SIGNATURES ONLY: finding one proves the software is running, not that
# bandwidth is being abused. Network-usage evidence is a separate signal
# to be added later, not derived from process names.
PROXY_KEYWORDS='xrayr|v2bx'
MINING_KEYWORDS='xmrig|minerd|ethminer|cpuminer|stratum'
SPEEDTEST_KEYWORDS='\bspeedtest\b|ookla|openspeedtest|librespeed|\biperf[0-9]*\b|fast\.com'

# --- Enforcement policy ----------------------------------------------------------
# All configured prohibited categories default to container shutdown.
# A qualifying match stops the container during the current service invocation.
ENFORCEMENT_MODE=stop

# --- Evidence limits --------------------------------------------------------------
# One process argument can be enormous; cap both line count and characters.
MAX_EVIDENCE_LINES_PER_CATEGORY=5
MAX_EVIDENCE_CHARS_PER_CATEGORY=600
MAX_EVIDENCE_TOTAL_CHARS=2500

# --- System -------------------------------------------------------------------------
# Hardcoded absolute path. Never trust an inherited PODMAN_BIN from the
# environment to select a different executable when running as root.
PODMAN_BIN=/usr/bin/podman

LOG_TAG="${LOG_TAG:-podcheck}"

VERBOSE=0
CMD=scan
while [ "$#" -gt 0 ]; do
    case "$1" in
        --verbose)
            VERBOSE=1
            ;;
        --install)
            CMD=install
            ;;
        --uninstall)
            CMD=uninstall
            ;;
        --status)
            CMD=status
            ;;
        -h|--help)
            CMD=help
            ;;
        *)
            printf 'Usage: %s [--install|--uninstall|--status|--help] [--verbose]\n' "$0" >&2
            exit 2
            ;;
    esac
    shift
done

# ==============================================================================
# 1. Environment compatibility
# ==============================================================================
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

HOST_LABEL=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf 'unknown')

log_msg() {
    local message="$1"
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" -- "$message"
    fi
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$message" >&2
}

debug_msg() {
    [ "$VERBOSE" -eq 1 ] || return 0
    log_msg "DEBUG: $1"
}

html_escape() {
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

# ==============================================================================
# 2. Telegram notification (bounded network behavior, no secret leakage)
# ==============================================================================
send_telegram_msg() {
    local message="$1"
    local response
    local api_url="https://api.telegram.org/bot${TG_TOKEN}/sendMessage"

    if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT_ID" ]; then
        log_msg "Telegram credentials not configured; skipping notification"
        return 1
    fi

    # URL-encoding is required in addition to HTML escaping: captured process
    # arguments may contain & + % = which would otherwise corrupt form-data.
    if ! response=$(curl -fsS \
        --connect-timeout 5 \
        --max-time 15 \
        --retry 2 \
        -X POST "$api_url" \
        --data-urlencode "chat_id=${TG_CHAT_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "text=${message}" 2>&1); then
        # Scrub the token from any error text before logging a response.
        response=$(printf '%s' "$response" | sed "s#${TG_TOKEN}#[REDACTED]#g")
        log_msg "Failed to send Telegram notification: ${response}"
        return 1
    fi
}

# ==============================================================================
# 3. Signature check - suspicious-software tripwire, NOT bandwidth-abuse proof
# ==============================================================================
# Appends to per-container result globals when a signature matches:
#   DETECTED_CATEGORIES, VIOLATIONS, VIOLATIONS_LIST, EVIDENCE, STOP_REQUESTED
check_category() {
    local key="$1" label="$2" pattern="$3" procs="$4"
    local matched block comms safe_comms len

    if ! printf '%s\n' "$procs" | grep -Ei -q "$pattern"; then
        return 0
    fi

    # Evidence order: select relevant lines, then truncate the raw text.
    matched=$(printf '%s\n' "$procs" | grep -Ei "$pattern" | head -n "$MAX_EVIDENCE_LINES_PER_CATEGORY" || true)
    [ -z "$matched" ] && return 0

    len=$(printf '%s' "$matched" | wc -c)
    if [ "$len" -gt "$MAX_EVIDENCE_CHARS_PER_CATEGORY" ]; then
        matched=$(printf '%s' "$matched" | head -c "$MAX_EVIDENCE_CHARS_PER_CATEGORY")
        matched="${matched}
[... evidence truncated ...]"
    fi

    comms=$(printf '%s\n' "$matched" | awk '{print $3}' | sort -u | paste -sd ',' -)
    [ -z "$comms" ] && comms="$key"
    safe_comms=$(printf '%s' "$comms" | html_escape)

    DETECTED_CATEGORIES="${DETECTED_CATEGORIES}${DETECTED_CATEGORIES:+, }${label}"
    VIOLATIONS="${VIOLATIONS}${VIOLATIONS:+; }${label}: ${comms}"
    if [ -n "$VIOLATIONS_LIST" ]; then
        VIOLATIONS_LIST="${VIOLATIONS_LIST}
- ${label}: ${safe_comms}"
    else
        VIOLATIONS_LIST="- ${label}: ${safe_comms}"
    fi

    # HTML escape the already-truncated text, then wrap in markup. Never wrap
    # the whole EVIDENCE string again inside another <pre><code> at message
    # build time: each category block is already self-contained.
    block=$(printf '%s' "$matched" | html_escape)
    EVIDENCE="${EVIDENCE}<b>${label}:</b>
<pre><code>${block}</code></pre>
"

    STOP_REQUESTED=1
    return 0
}

# ==============================================================================
# 3b. Admin subcommands: self-install, uninstall, status, help
# ==============================================================================
# The systemd units are generated at install time from the templates below and
# are the single source of truth for how the scanner is launched.  Keeping them
# inside this script leaves podcheck.sh as the only file to ship and prevents
# drift between the scanner and the units.

SERVICE_UNIT='[Unit]
Description=Podman prohibited process scanner

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/podcheck.sh
EnvironmentFile=-/etc/podcheck.env

User=root
Group=root
UMask=0077

TimeoutStartSec=120

StandardOutput=journal
StandardError=journal
'

TIMER_UNIT='[Unit]
Description=Run Podman prohibited process scanner periodically

[Timer]
OnBootSec=2min
OnUnitInactiveSec=3min
Unit=podcheck.service

[Install]
WantedBy=timers.target
'

ENV_TEMPLATE='# podcheck environment configuration
# Fill in real values; loaded by podcheck.service via EnvironmentFile=-.
TG_TOKEN=""
TG_CHAT_ID=""
'

SERVICE_PATH=/etc/systemd/system/podcheck.service
TIMER_PATH=/etc/systemd/system/podcheck.timer
ENV_PATH=/etc/podcheck.env
INSTALL_PATH=/usr/local/sbin/podcheck.sh
LOCK_FILE=/run/podcheck.lock

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf 'podcheck: %s must be run as root\n' "$1" >&2
        exit 1
    fi
}

warn_cron_conflict() {
    if crontab -l 2>/dev/null | grep -q 'podcheck'; then
        printf 'WARNING: a cron entry still runs podcheck.sh; remove it so the\n' >&2
        printf 'script is not launched by both cron and systemd (crontab -e):\n' >&2
        crontab -l 2>/dev/null | grep 'podcheck' >&2
    fi
}

do_install() {
    require_root "--install"
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'podcheck: systemctl not found; systemd is required\n' >&2
        exit 1
    fi

    install -m 0755 -o root -g root "$0" "$INSTALL_PATH"
    printf '%s' "$SERVICE_UNIT" > "$SERVICE_PATH"
    printf '%s' "$TIMER_UNIT" > "$TIMER_PATH"

    if [ -f "$ENV_PATH" ]; then
        printf 'podcheck: %s already exists; leaving it unchanged\n' "$ENV_PATH"
    else
        printf '%s' "$ENV_TEMPLATE" > "$ENV_PATH"
        chmod 0600 "$ENV_PATH"
        printf 'podcheck: created %s - set TG_TOKEN/TG_CHAT_ID\n' "$ENV_PATH"
    fi

    systemctl daemon-reload
    systemctl enable --now podcheck.timer

    warn_cron_conflict
    printf 'podcheck: installed. Verify with: %s --status\n' "$0"
}

do_uninstall() {
    require_root "--uninstall"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now podcheck.timer >/dev/null 2>&1
    fi
    rm -f "$SERVICE_PATH" "$TIMER_PATH" "$LOCK_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    warn_cron_conflict
    printf 'podcheck: removed %s, %s and %s\n' "$SERVICE_PATH" "$TIMER_PATH" "$LOCK_FILE"
    printf 'podcheck: left %s (Telegram credentials) and %s in place; remove manually if desired\n' "$ENV_PATH" "$INSTALL_PATH"
}

do_status() {
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'podcheck: systemctl not found; not installed via systemd\n' >&2
        exit 1
    fi
    if [ ! -f "$SERVICE_PATH" ] && [ ! -f "$TIMER_PATH" ]; then
        printf 'podcheck: not installed (no %s / %s)\n' "$TIMER_PATH" "$SERVICE_PATH"
        printf 'podcheck: install with: %s --install\n' "$0"
        exit 1
    fi
    printf '==== podcheck.timer ====\n'
    systemctl status podcheck.timer --no-pager 2>&1 | head -n 20
    printf '\n==== podcheck.service ====\n'
    systemctl status podcheck.service --no-pager 2>&1 | head -n 20
    printf '\n==== list-timers podcheck.timer ====\n'
    systemctl list-timers podcheck.timer --no-pager 2>&1
    printf '\n==== journalctl -u podcheck.service (last 20) ====\n'
    journalctl -u podcheck.service --no-pager -n 20 2>&1
}

do_help() {
    cat <<EOF
Usage: $0 [ACTION] [--verbose]

Actions (default: scan):
  --install     Deploy as a systemd oneshot service + timer (root required)
  --uninstall   Remove the systemd units, timer and stale lock (root required)
  --status      Show timer/service status, next run and recent logs
  --verbose     Verbose output during a scan
  --help        Show this help

Scan exit codes:
  0  scan completed successfully (including violations detected and stopped)
  1  monitoring infrastructure failure
  2  invalid arguments or configuration

podcheck.sh is a prohibited/suspicious process signature scanner for Podman
containers using host-side 'podman top'. It is not a bandwidth-abuse detector.
Tenant containers must NOT be granted CAP_SYS_PTRACE.
EOF
    exit 0
}

case "$CMD" in
    scan) ;;
    install)   do_install; exit $? ;;
    uninstall) do_uninstall; exit $? ;;
    status)    do_status; exit $? ;;
    help)      do_help ;;
esac

# ==============================================================================
# 4. Container scan
# ==============================================================================
# Defense in depth: prevent concurrent invocations (systemd timer overlaps a
# manual run, or a straggler from a previous timer tick).
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log_msg "Another podcheck instance is already running; skipping"
    exit 0
fi

if ! command -v "$PODMAN_BIN" >/dev/null 2>&1; then
    log_msg "Podman executable not found: ${PODMAN_BIN}"
    exit 1
fi

debug_msg "Using podman command: ${PODMAN_BIN}"
debug_msg "Enforcement mode: ${ENFORCEMENT_MODE}"

# Enumerate containers; a failure here must not look like an empty scan.
if ! containers=$("$PODMAN_BIN" ps --format '{{.ID}} {{.Names}}'); then
    log_msg "Failed to enumerate Podman containers"
    exit 1
fi

if [ -z "$containers" ]; then
    debug_msg "No running containers"
    exit 0
fi

while read -r cid cname; do
    [ -z "$cid" ] && continue
    debug_msg "Inspecting container: ${cname} (${cid})"

    # Host-side process inspection; does not require ps inside the container.
    if ! procs=$("$PODMAN_BIN" top "$cid" pid hpid comm args 2>/dev/null); then
        log_msg "podman top failed for container ${cname} (${cid}); continuing scan"
        continue
    fi
    if [ -z "$procs" ]; then
        debug_msg "No process output for container ${cname} (${cid})"
        continue
    fi
    # Drop the table header (PID HOSTPID COMMAND ARGS).
    procs=$(printf '%s\n' "$procs" | tail -n +2)

    DETECTED_CATEGORIES=""
    VIOLATIONS=""
    VIOLATIONS_LIST=""
    EVIDENCE=""
    STOP_REQUESTED=0

    check_category proxy "Proxy software" "$PROXY_KEYWORDS" "$procs"
    check_category mining "Mining software" "$MINING_KEYWORDS" "$procs"
    check_category speedtest "Speed testing software" "$SPEEDTEST_KEYWORDS" "$procs"

    if [ -z "$DETECTED_CATEGORIES" ]; then
        debug_msg "No prohibited software signatures in container ${cname} (${cid})"
        continue
    fi

    log_msg "incident host=${HOST_LABEL} container=${cname} container_id=${cid} violations=[${VIOLATIONS}]"

    # Enforcement: evidence was recorded above; never re-collect after stop.
    if [ "$STOP_REQUESTED" -eq 1 ]; then
        if "$PODMAN_BIN" stop -t 2 "$cid" >/dev/null 2>&1; then
            STOP_RESULT="success"
        else
            STOP_RESULT="failed"
            log_msg "Failed to stop container ${cname} (${cid})"
        fi
    else
        STOP_RESULT="n/a"
    fi

    ACTION="alert"
    [ "$STOP_REQUESTED" -eq 1 ] && ACTION="stop"
    log_msg "incident_enforcement host=${HOST_LABEL} container=${cname} container_id=${cid} action=${ACTION} result=${STOP_RESULT} violations=[${VIOLATIONS}]"

    HOST_ESCAPED=$(printf '%s' "$HOST_LABEL" | html_escape)
    CNAME_ESCAPED=$(printf '%s' "$cname" | html_escape)
    CID_ESCAPED=$(printf '%s' "$cid" | html_escape)

    if [ "$STOP_RESULT" = "success" ]; then
        DISPOSITION="<b>container shutdown initiated</b> — <code>podman stop -t 2 executed</code>；若未能在 2 秒内正常退出，将被强制终止。"
    else
        DISPOSITION="<b>container shutdown initiated</b> — 已尝试执行 <code>podman stop -t 2</code> 但操作失败，请人工介入检查容器 <code>${CID_ESCAPED}</code>。"
    fi

    if [ "$(printf '%s' "$EVIDENCE" | wc -c)" -gt "$MAX_EVIDENCE_TOTAL_CHARS" ]; then
        EVIDENCE=$(printf '%s' "$EVIDENCE" | head -c "$MAX_EVIDENCE_TOTAL_CHARS")
        EVIDENCE="${EVIDENCE}
[... evidence truncated ...]"
    fi

    MSG="⚠️ <b>安全策略触发：检测到违规软件</b> ⚠️
<b>prohibited process detected</b>

<b>服务器:</b> <code>${HOST_ESCAPED}</code>
<b>容器名称:</b> <code>${CNAME_ESCAPED}</code>
<b>容器 ID:</b> <code>${CID_ESCAPED}</code>

<b>检测到:</b>
${VIOLATIONS_LIST}

<b>触发现场(部分进程):</b>
${EVIDENCE}
<b>处置:</b> ${DISPOSITION}"

    # Notification is the LAST step; a Telegram failure never blocks
    # local logging or enforcement.
    send_telegram_msg "$MSG"
done <<< "$containers"

exit 0
