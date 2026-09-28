#!/bin/sh
set -eu
: "${SNMPV3_USER:=labmonitor}"
: "${SNMPV3_AUTH_PASS:?SNMPV3_AUTH_PASS must be injected at runtime}"
: "${SNMPV3_PRIV_PASS:?SNMPV3_PRIV_PASS must be injected at runtime}"
cat > /run/snmpd.conf <<EOF
# Use an unprivileged lab port so the collector remains portable across
# rootless/container runtimes. The SNMP client must target UDP/1161.
agentAddress udp:0.0.0.0:1161
createUser ${SNMPV3_USER} SHA "${SNMPV3_AUTH_PASS}" AES "${SNMPV3_PRIV_PASS}"
rouser ${SNMPV3_USER} authPriv
sysLocation FLOWWM-LAB
sysName core-switch
EOF
exec snmpd -f -Le -c /run/snmpd.conf
