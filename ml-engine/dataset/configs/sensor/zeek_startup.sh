#!/bin/sh
# Supervised Zeek/TCPDump capture lifecycle.
# The sensor is intentionally fail-closed: if either collector exits, the
# supervisor terminates the other collector so partial campaigns are not
# mistaken for complete telemetry.
set -eu

LOG_DIR=/usr/local/zeek/logs
PCAP_DIR=/usr/local/zeek/logs
ZEEK_PID=""
TCPDUMP_PID=""

shutdown() {
    status=$?
    trap - INT TERM EXIT
    if [ -n "$ZEEK_PID" ] && kill -0 "$ZEEK_PID" 2>/dev/null; then
        kill -TERM "$ZEEK_PID" 2>/dev/null || true
    fi
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
    fi
    [ -n "$ZEEK_PID" ] && wait "$ZEEK_PID" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && wait "$TCPDUMP_PID" 2>/dev/null || true
    exit "$status"
}
trap shutdown INT TERM EXIT

sed -i 's/LogASCII::use_json = F/LogASCII::use_json = T/g' /usr/local/zeek/share/zeek/site/local.zeek

# Wait for interface to be up
echo "Waiting for eth1 to appear..."
while [ ! -d /sys/class/net/eth1 ]; do
    sleep 1
done
echo "eth1 found."
sleep 2
# Strip IP and put in promiscuous mode (Dual-Homed SPAN Architecture)
ip addr flush dev eth1 || ifconfig eth1 0.0.0.0
ip link set eth1 promisc on || ifconfig eth1 promisc

sleep 2

# Start processes
echo "Starting Zeek..."
mkdir -p "$LOG_DIR" "$PCAP_DIR"
cd "$LOG_DIR"
zeek -i eth1 -C local > zeek_supervisor.log 2>&1 &
ZEEK_PID=$!

echo "Starting rotating tcpdump capture..."
tcpdump -i eth1 -nn -s 0 -G 3600 -W 24 \
    -w "$PCAP_DIR/flowwm-%Y%m%d-%H%M%S.pcap" \
    > tcpdump.log 2>&1 &
TCPDUMP_PID=$!

echo "Capture lifecycle active. Supervising PIDs: Zeek($ZEEK_PID), tcpdump($TCPDUMP_PID)"

# Supervision loop
while true; do
    if ! kill -0 "$ZEEK_PID" 2>/dev/null; then
        echo "[FATAL] Zeek process died; stopping tcpdump." >&2
        exit 1
    fi
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo "[FATAL] tcpdump process died; stopping Zeek." >&2
        exit 1
    fi
    sleep 5
done
