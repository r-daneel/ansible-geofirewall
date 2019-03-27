#!/bin/bash

# Firewall script

function SetColor() {
  [ ${USE_COLORS:-1} -eq 0 ] && return 0
  sc_color="${1}"
  case "${sc_color}" in
    grey) sc_colorcode="0" ;;
    blue) sc_colorcode="1" ;;
    green) sc_colorcode="2" ;;
    cyan) sc_colorcode="3" ;;
    red) sc_colorcode="4" ;;
    purple) sc_colorcode="5" ;;
    yellow) sc_colorcode="6" ;;
    white) sc_colorcode="7" ;;
    *) sc_colorcode="7" ;;
  esac
  tput setf "${sc_colorcode}" || return 1
  return 0
}

function ResetColor() {
  [ ${USE_COLORS:-1} -eq 0 ] && return 0
  SetColor || return 1
  return 0
}

function WriteInfo() {
  wi_DateTimeStamp=$(date +%d/%m/%Y-%H:%M:%S)
  SetColor green
  echo "${wi_DateTimeStamp} INFO: ${1}"
  ResetColor
  return 0
}

function WriteWarn() {
  ww_DateTimeStamp=$(date +%d/%m/%Y-%H:%M:%S)
  SetColor yellow
  echo "${ww_DateTimeStamp} WARNING: ${1}"
  ResetColor
  return 0
}

function WriteErr() {
  we_DateTimeStamp=$(date +%d/%m/%Y-%H:%M:%S)
  SetColor red
  echo "${we_DateTimeStamp} ERROR: ${1}" >&2
  ResetColor
  return 0
}

function WriteDebug() {
  [ ${DEBUG:-1} -eq 0 ] && return 0
  SetColor blue
  wd_DateTimeStamp=$(date +%d/%m/%Y-%H:%M:%S)
  echo "${wd_DateTimeStamp} DEBUG: ${1}"
  ResetColor
  return 0
}

function ExitScript() {
  es_status="${1}"
  es_message="${2}"
  [ -z "${es_status}" ] && es_status=0
  [ -z "${es_message}" ] && es_message="exit status is '${es_status}'"
  [ ${es_status} -eq 0 ] && WriteInfo "${es_message}" || WriteErr "${es_message}";
  exit ${es_status}
}

function isTty() {
        # if stdout(1) and stderr(2) are ttys, return true
        [ -t 1 ] && [ -t 2 ] && return 0
        return 1
}

function Usage() {
  echo "usage: ${0}"
  return 0
}

function checkGEOIP() {
  WriteDebug "checking for geoip"
  modprobe xt_geoip &>/dev/null || { WriteDebug "geoip not found"; return 1; }
  WriteDebug "found geoip enabled"
  return 0
}

function checkIPV6() {
  WriteDebug "checking for IPv6"
  lsmod | grep -q ipv6 && { WriteDebug "found IPv6 enabled"; return 0; }
  WriteDebug "found IPv6 disabled"
  return 1
}

function iptablesCmd() {
  WriteDebug "run: '${IPTABLES} ${*}'"
  ${IPTABLES} ${*} && return 0
  WriteErr "iptablesCmd ${*} failed"
  return 1
}

function ip6tablesCmd() {
  WriteDebug "run: '${IP6TABLES} ${*}'"
  [ ${HAVE_IPV6} -eq 0 ] && { WriteDebug "IPv6 disabled/not present. Skipping."; return 0; }
  ${IP6TABLES} ${*} && return 0
  WriteErr "ip6tablesCmd ${*} failed"
  return 1
}

#
# basic way to identify IPv4 from IPv6
# this assumes IP is already 'valid'
#
function isIPv4() {
  [ "${1//./_}" == "${1}" ] && return 1
  return 0
}

#
# basic way to identify IPv6 from IPv4
# this assumes IP is already 'valid'
#
function isIPv6() {
  [ "${1//:/_}" == "${1}" ] && return 1
  return 0
}

function clearAllRules() {
  WriteInfo "clearing all rules ..."

  for item in ${ALL_TABLES_AND_CHAINS}; do
    current_table=${item%%:*}
    current_table_chains=${item#*:}
    for current_chain in ${current_table_chains//:/ }; do
      iptablesCmd --table "${current_table}" --policy "${current_chain}" ACCEPT || return 1
      ip6tablesCmd --table "${current_table}" --policy "${current_chain}" ACCEPT || return 1
    done
    iptablesCmd --table "${current_table}" --flush || return 1
    iptablesCmd --table "${current_table}" --delete-chain || return 1
    ip6tablesCmd --table "${current_table}" --flush || return 1
    ip6tablesCmd --table "${current_table}" --delete-chain || return 1
  done

  return 0
}

function acceptLocalConnections() {
  iptablesCmd -A INPUT -i lo -j ACCEPT || return 1
  iptablesCmd -A OUTPUT -o lo -j ACCEPT || return 1
  ip6tablesCmd -A INPUT -i lo -j ACCEPT || return 1
  ip6tablesCmd -A OUTPUT -o lo -j ACCEPT || return 1
  return 0
}

function acceptEstablishedConnections() {
  iptablesCmd -A INPUT  -m state --state RELATED,ESTABLISHED -j ACCEPT || return 1
  iptablesCmd -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT || return 1
  ip6tablesCmd -A INPUT  -m state --state RELATED,ESTABLISHED -j ACCEPT || return 1
  ip6tablesCmd -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT || return 1
  return 0
}

function getSystemNameServers(){
  [ -r "${RESOLV_CONF_FILE}" ] || { WriteErr "file '${RESOLV_CONF_FILE}' not found or not readable"; return 1; }
  awk '$1=="nameserver" { print $2 }' "${RESOLV_CONF_FILE}" && return 0
  WriteErr "failed getting nameservers from '${RESOLV_CONF_FILE}'"
  return 1
}

function allowNameServers() {
  aNS_servers="${*}"

  if [ -z "${aNS_servers}" ]; then
    WriteInfo "no nameserver set in \${DNS_allowed_servers}, auto-guessing from '${RESOLV_CONF_FILE}'"
    aNS_servers=$(getSystemNameServers) || return 1
    WriteDebug "gathered nameservers: '${aNS_servers}'"
    [ -z "${aNS_servers}" ] && WriteWarn "oddly we did find no nameservers in '${RESOLV_CONF_FILE}'. Hope this is OK"
  fi

  if [ -z "${aNS_servers}" ]; then
    # failopen, at least DNS is working ;)
    WriteWarn "no nameserver set, allowing all outgoing DNS queries"
    iptablesCmd -A OUTPUT -m state --state NEW -p udp --dport 53 -j ACCEPT || return 1
    iptablesCmd -A OUTPUT -m state --state NEW -p tcp --dport 53 -j ACCEPT || return 1
    ip6tablesCmd -A OUTPUT -m state --state NEW -p udp --dport 53 -j ACCEPT || return 1
    ip6tablesCmd -A OUTPUT -m state --state NEW -p tcp --dport 53 -j ACCEPT || return 1
    return 0
  fi

  for current_host in ${aNS_servers}
  do
    WriteDebug "allowing DNS queries to host nameserver '${current_host}'"
    if $(isIPv4 "${current_host}"); then
      iptablesCmd -A OUTPUT -m state --state NEW -d ${current_host} -p udp --dport 53 -j ACCEPT || return 1
      iptablesCmd -A OUTPUT -m state --state NEW -d ${current_host} -p tcp --dport 53 -j ACCEPT || return 1
    elif $(isIPv6 "${current_host}"); then
      ip6tablesCmd -A OUTPUT -m state --state NEW -d ${current_host} -p udp --dport 53 -j ACCEPT || return 1
      ip6tablesCmd -A OUTPUT -m state --state NEW -d ${current_host} -p tcp --dport 53 -j ACCEPT || return 1
    else
      WriteWarn "'${current_host}' not a valid IPv4 or IPv6 CIDR, skipping entry"
    fi
  done
  return 0
}

function setDefaultPolicies() {
  sDP_policy="${1:=ACCEPT}"
  iptablesCmd -P INPUT "${sDP_policy}" || return 1
  iptablesCmd -P FORWARD "${sDP_policy}" || return 1
  iptablesCmd -P OUTPUT "${sDP_policy}" || return 1
  ip6tablesCmd -P INPUT "${sDP_policy}" || return 1
  ip6tablesCmd -P FORWARD "${sDP_policy}" || return 1
  ip6tablesCmd -P OUTPUT "${sDP_policy}" || return 1
  return 0
}

function addNewChain() {
  aNC_chain="${1}"
  [ -z "${aNC_chain}" ] && { WriteErr "no chain name supplied to function 'addNewChain'"; return 1; }
  iptablesCmd -N "${aNC_chain}" || return 1
  ip6tablesCmd -N "${aNC_chain}" || return 1
  return 0
}

#
# main()
#
bin_path=$(readlink -f "${0}")
bin_dir=$(dirname "${bin_path}")

# use colors in Write* functions (this defaults to 0)
USE_COLORS=0
# if stdout(1) and stderr(2) are ttys, enable colors
isTty && USE_COLORS=1

# set debug mode to 0 if not previously set (ouside the script)
[ -z "${DEBUG}" ] && DEBUG=0

[ ${DEBUG} -eq 0 ] || WriteInfo "DEBUG mode active"

# iptables binaries
IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
IPTABLES_SAVE="/sbin/iptables-save"
IP6TABLES_SAVE="/sbin/ip6tables-save"

# this comes with your distribution, usually
IPTABLES_DIR="/etc/iptables"
IPTABLES_IPV4_RULES_FILE="${IPTABLES_DIR}/rules.v4"
IPTABLES_IPV6_RULES_FILE="${IPTABLES_DIR}/rules.v6"

ALL_TABLES_AND_CHAINS="
  filter:INPUT:FORWARD:OUTPUT
  nat:PREROUTING:OUTPUT:POSTROUTING
  mangle:PREROUTING:INPUT:FORWARD:OUTPUT:POSTROUTING
  raw:PREROUTING:OUTPUT
  security:INPUT:FORWARD:OUTPUT
"

# config file
CONFIG_FILE="/etc/$(basename ${0%*.sh}).conf"

# standard resolv.conf file
RESOLV_CONF_FILE="/etc/resolv.conf"

# initialize variables
DNS_allowed_servers=""

SERVICES_allowed_hosts=""
# not implemented
#SERVICES_denied_hosts=""

SERVICES_allowed_countries=""
# not implemented
#SERVICES_denied_countries=""

SERVICES_allowed_ports=""

ADMIN_allowed_hosts=""
# not implemented
#ADMIN_denied_hosts=""

ADMIN_allowed_countries=""
# not implemented
#ADMIN_denied_countries=""

ADMIN_allowed_ports=""

MONITORING_allowed_hosts=""
# not implemented
#MONITORING_denied_hosts=""

MONITORING_allowed_countries=""
# not implemented
#MONITORING_denied_countries=""

MONITORING_allowed_ports=""

OUTPUT_allowed_ports=""

#INPUT_ignored_destination_ports=""

#INPUT_ignored_source_hosts=""

#INPUT_ignored_destination_hosts=""

LOG_DROPPED_PACKETS="0"

if [ -r "${CONFIG_FILE}" ]; then
  WriteInfo "loading configuration file '${CONFIG_FILE}'"
else
  ExitScript 1 "configuraton file '${CONFIG_FILE}' not found"
fi

# sourcing configuration file
. "${CONFIG_FILE}" || ExitScript 1 "failed loading '${CONFIG_FILE}'"

# check if ipv6 is loaded
HAVE_IPV6=0
checkIPV6 && HAVE_IPV6=1

# check if geoip is loaded
HAVE_GEOIP=0
checkGEOIP && HAVE_GEOIP=1

managed_chains="ADMIN MONITORING SERVICES"

#
# check if we are in test mode (failsafe)
#
if [ ${test_mode:=1} -eq 0 ]; then
  WriteInfo "test mode DISABLED, we WILL DROP packets"
  default_policy="DROP"
else
  WriteInfo "test mode ENABLED, we WILL NOT DROP packets"
  default_policy="ACCEPT"
fi

#
# signal if we have geoip
#
[ ${HAVE_GEOIP} -eq 0 ] && WriteInfo "geoip not available" || WriteInfo "geoip available"

#
# clear all firewall rules
#
clearAllRules || ExitScript 1 "clearAllRules failed"

#
# load new rules
#
WriteInfo "loading new rule-set ..."

#
# accept local connections
#
acceptLocalConnections || ExitScript 1 "'acceptLocalConnections' failed"

#
# accept established connections
#
acceptEstablishedConnections || ExitScript 1 "'acceptEstablishedConnections' failed"

#
# allow dns queries only to allowed servers (if provided)
#
allowNameServers ${DNS_allowed_servers} || ExitScript 1 "'allowNameServers ${DNS_allowed_servers}' failed"

#
# now that all established connections are allowed
# we set restrictive policies
#
WriteInfo "setting default policies to '${default_policy}'"
setDefaultPolicies "${default_policy}" || ExitScript 1 "'setDefaultPolicies' failed"

#
# create new chains
#
for current_chain in ${managed_chains}
do
  WriteInfo "adding new chain '${current_chain}'"
  addNewChain "${current_chain}" || ExitScript 1 "'addNewChain ${current_chain}' failed"
done

#
# allow selected hosts to ADMIN chain
#
for CIDR in ${ADMIN_allowed_hosts}
do
  WriteInfo "accepting '${CIDR}' in ADMIN chain"
  if $(isIPv4 "${CIDR}"); then
    iptablesCmd -A ADMIN -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  elif $(isIPv6 "${CIDR}"); then
    ip6tablesCmd -A ADMIN -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  else
    WriteWarn "'${CIDR}' not a valid IPv4 or IPv6 CIDR, skipping entry"
  fi
done

#
# allow selected countries to ADMIN chain
#
if [ ${HAVE_GEOIP} -eq 1 ]; then
  # allow these countries for admin
  for current_country in ${ADMIN_allowed_countries}
  do
    WriteInfo "accepting '${current_country}' in ADMIN chain"
    iptablesCmd -A ADMIN -m geoip --src-cc ${current_country} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  done
else
  WriteInfo "geoip module not found, skipping country based rules for ADMIN chain"
fi

#
# ADMIN_allowed_ports go through ADMIN chain
#
for current_port in ${ADMIN_allowed_ports}
do
  current_port_protocols="${current_port#*/}"
  current_port=${current_port%%/*}
  for current_protocol in ${current_port_protocols//\// }
  do
    case "${current_protocol,,}" in
    icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port}' to ADMIN chain"
      iptablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --icmp-type ${current_port} -j ADMIN || ExitScript 1 "iptablesCmd failed"
      ;;
    ipv6-icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port//#//}' to ADMIN chain"
      ip6tablesCmd -A INPUT -p ${current_protocol} -j ADMIN || ExitScript 1 "ip6tablesCmd failed"
      ;;
    *)
      WriteInfo "sending incoming connections for port '${current_port}/${current_protocol}' to ADMIN chain"
      iptablesCmd  -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j ADMIN || ExitScript 1 "iptablesCmd failed"
      ip6tablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j ADMIN || ExitScript 1 "ip6tablesCmd failed"
      ;;
    esac
  done
done

#
# allow selected hosts to MONITORING chain
#
for CIDR in ${MONITORING_allowed_hosts}
do
  WriteInfo "accepting '${CIDR}' in MONITORING chain"
  if $(isIPv4 "${CIDR}"); then
    iptablesCmd -A MONITORING -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  elif $(isIPv6 "${CIDR}"); then
    ip6tablesCmd -A MONITORING -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  else
    WriteWarn "'${CIDR}' not a valid IPv4 or IPv6 CIDR, skipping entry"
  fi
done

#
# allow selected countries to MONITORING chain
#
if [ ${HAVE_GEOIP} -eq 1 ]; then
  # allow these countries for admin
  for current_country in ${MONITORING_allowed_countries}
  do
    WriteInfo "accepting '${current_country}' in MONITORING chain"
    iptablesCmd -A MONITORING -m geoip --src-cc ${current_country} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
    ip6tablesCmd -A MONITORING -m geoip --src-cc ${current_country} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  done
else
  WriteInfo "geoip module not found, skipping country based rules for MONITORING chain"
fi

#
# MONITORING_allowed_ports go through MONITORING chain
#
for current_port in ${MONITORING_allowed_ports}
do
  current_port_protocols="${current_port#*/}"
  current_port=${current_port%%/*}
  for current_protocol in ${current_port_protocols//\// }
  do
    case "${current_protocol,,}" in
    icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port}' to MONITORING chain"
      iptablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --icmp-type ${current_port} -j MONITORING || ExitScript 1 "iptablesCmd failed"
      ;;
    ipv6-icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port//#//}' to MONITORING chain"
      ip6tablesCmd -A INPUT -p ${current_protocol} -j MONITORING || ExitScript 1 "ip6tablesCmd failed"
#      ip6tablesCmd -A INPUT -p ${current_protocol} --icmpv6-type ${current_port//#//} -j MONITORING || ExitScript 1 "ip6tablesCmd failed"
      ;;
    *)
      WriteInfo "sending incoming connections for port '${current_port}/${current_protocol}' to MONITORING chain"
      iptablesCmd  -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j MONITORING || ExitScript 1 "iptablesCmd failed"
      ip6tablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j MONITORING || ExitScript 1 "ip6tablesCmd failed"
      ;;
    esac
  done
done

#
# allow selected hosts to SERVICES chain
#
for CIDR in ${SERVICES_allowed_hosts}
do
  WriteInfo "accepting '${CIDR}' in SERVICES chain"
  if $(isIPv4 "${CIDR}"); then
    iptablesCmd -A SERVICES -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  elif $(isIPv6 "${CIDR}"); then
    ip6tablesCmd -A SERVICES -s "${CIDR}" -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  else
    WriteWarn "'${CIDR}' not a valid IPv4 or IPv6 CIDR, skipping entry"
  fi
done

#
# allow selected countries to SERVICES chain
#
if [ ${HAVE_GEOIP} -eq 1 ]; then
  # allow only these sources for services
  for current_country in ${SERVICES_allowed_countries}
  do
    WriteInfo "accepting '${current_country}' in SERVICES chain"
    iptablesCmd  -A SERVICES -m geoip --src-cc ${current_country} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
    ip6tablesCmd -A SERVICES -m geoip --src-cc ${current_country} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  done
else
  WriteInfo "geoip module not found, skipping country based rules for SERVICES chain"
fi

#
# SERVICES_allowed_ports go through SERVICES chain
#
for current_port in ${SERVICES_allowed_ports}
do
  current_port_protocols="${current_port#*/}"
  current_port=${current_port%%/*}
  for current_protocol in ${current_port_protocols//\// }
  do
    case "${current_protocol,,}" in
    icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port}' to SERVICES chain"
      iptablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --icmp-type ${current_port} -j SERVICES || ExitScript 1 "iptablesCmd failed"
      ;;
    ipv6-icmp)
      WriteInfo "sending incoming '${current_protocol}:${current_port//#//}' to SERVICES chain"
      ip6tablesCmd -A INPUT -p ${current_protocol} -j SERVICES || ExitScript 1 "ip6tablesCmd failed"
      ;;
    *)
      WriteInfo "sending incoming connections for port '${current_port}/${current_protocol}' to SERVICES chain"
      iptablesCmd  -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j SERVICES || ExitScript 1 "iptablesCmd failed"
      ip6tablesCmd -A INPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j SERVICES || ExitScript 1 "ip6tablesCmd failed"
      ;;
    esac
  done
done


#
# allow things to go out
#
if [ ${OUTPUT_enable_filter:-0} -eq 0 ]; then
  WriteInfo "allowing all outgoing connections (\${OUTPUT_enable_filter}=0)"
  iptablesCmd  -A OUTPUT -j ACCEPT || ExitScript 1 "iptablesCmd failed"
  ip6tablesCmd -A OUTPUT -j ACCEPT || ExitScript 1 "ip6tablesCmd failed"
else
  for current_port in ${OUTPUT_allowed_ports}
  do
    current_port_protocols="${current_port#*/}"
    current_port=${current_port%%/*}
    for current_protocol in ${current_port_protocols//\// }
    do
      case "${current_protocol,,}" in
      icmp)
        WriteInfo "allowing outgoing '${current_protocol}:${current_port}'"
        iptablesCmd -A OUTPUT -m state --state NEW -p ${current_protocol} --icmp-type ${current_port} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
        ;;
      ipv6-icmp)
        WriteInfo "allowing outgoing '${current_protocol}:${current_port//#//}'"
        ip6tablesCmd -A OUTPUT -p ${current_protocol} -j ACCEPT || ExitScript 1 "ip6tablesCmd failed"
        ;;
      *)
        WriteInfo "allowing outgoing connection to port '${current_port}/${current_protocol}'"
        iptablesCmd  -A OUTPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j ACCEPT || ExitScript 1 "iptablesCmd failed"
        ip6tablesCmd -A OUTPUT -m state --state NEW -p ${current_protocol} --dport ${current_port} -j ACCEPT || ExitScript 1 "ip6tablesCmd failed"
        ;;
      esac
    done
  done
fi


##
## ignoring (dropping) known noise traffic silently (hosts)
##
#for current_host in ${INPUT_ignored_source_hosts}
#do
#  WriteInfo "ignoring incoming origin '${current_host}'"
#  iptablesCmd -A INPUT -s ${current_host} -j "${default_policy}" || ExitScript 1 "iptablesCmd failed"
#done
#
#for current_host in ${INPUT_ignored_destination_hosts}
#do
#  WriteDebug "ignoring incoming destination '${current_host}'"
#  iptablesCmd -A INPUT -d ${current_host} -j "${default_policy}" || ExitScript 1 "iptablesCmd failed"
#done
#
##
## ignoring (dropping) known noise traffic silently (ports)
##
#for current_port in ${INPUT_ignored_destination_ports}
#do
#  current_port_protocols="${current_port#*/}"
#  current_port=${current_port%%/*}
#  for current_protocol in ${current_port_protocols//\// }
#  do
#    if [ ${current_protocol,,} = "ICMP" ]; then
#      WriteInfo "ignoring incoming '${current_protocol}:${current_port}'"
#      iptablesCmd -A INPUT -p ${current_protocol} --icmp-type ${current_port} -j "${default_policy}" || ExitScript 1 "iptablesCmd failed"
#      #ip6tablesCmd -A INPUT -p ${current_protocol} --icmp-type ${current_port} -j "${default_policy}" || ExitScript 1 "ip6tablesCmd failed"
#    else
#      WriteInfo "ignoring incoming connection to port '${current_port}/${current_protocol}'"
#      iptablesCmd -A INPUT -p ${current_protocol} --dport ${current_port} -j "${default_policy}" || ExitScript 1 "iptablesCmd failed"
#      ip6tablesCmd -A INPUT -p ${current_protocol} --dport ${current_port} -j "${default_policy}" || ExitScript 1 "ip6tablesCmd failed"
#    fi
#  done
#done

#
# seems we drop&log outgoing RST packets that we send out after conntrack timeout
# just discarding them on purpose for any SERVICES_port as a source
#
WriteDebug "ignoring RST packets of timed-out connections"
for current_port in ${SERVICES_allowed_ports}
do
  current_port_protocols="${current_port#*/}"
  current_port=${current_port%%/*}
  for current_protocol in ${current_port_protocols//\// }
  do
    case "${current_protocol,,}" in
    icmp)
      WriteDebug "we do no supplemental processing for ICMP packets here"
      ;;
    udp)
      WriteDebug "we do no supplemental processing for UDP packets here"
      ;;
    tcp)
      WriteInfo "dropping any outgoing RST packet from known service port '${current_port}/${current_protocol}'"
      iptablesCmd -A OUTPUT -p ${current_protocol} --sport ${current_port} -m tcp --tcp-flags ALL RST,ACK -j "${default_policy}" || ExitScript 1 "iptablesCmd failed"
      ip6tablesCmd -A OUTPUT -p ${current_protocol} --sport ${current_port} -m tcp --tcp-flags ALL RST,ACK -j "${default_policy}" || ExitScript 1 "ip6tablesCmd failed"
      ;;
    *)
      WriteWarn "unknown protocol '${current_protocol}'"
    esac
  done
done

#
# last rule logs anything not matched before policy drops it
#
if [ ${LOG_DROPPED_PACKETS} -eq 1 ]; then
  WriteDebug "logging any other packet"
  for current_chain in INPUT FORWARD OUTPUT
  do
    iptablesCmd -A "${current_chain}" -j LOG --log-prefix "${default_policy}_${current_chain}:" || ExitScript 1 "iptablesCmd failed"
    ip6tablesCmd -A "${current_chain}" -j LOG --log-prefix "${default_policy}_${current_chain}_IPV6:" || ExitScript 1 "ip6tablesCmd failed"
  done
fi

#
# saving rules for next reboots
#
if [ -d "${IPTABLES_DIR}" ]; then
  WriteInfo "saving newly applied rules ..."
  if [ -r "${IPTABLES_IPV4_RULES_FILE}" ]; then
    iptables_IPv4_rules_backup_file="${IPTABLES_IPV4_RULES_FILE}_$(date +%Y%m%d-%H%M%S)"
    WriteInfo "backing up file '${IPTABLES_IPV4_RULES_FILE}' to '${iptables_IPv4_rules_backup_file}' ..."
    cp -p "${IPTABLES_IPV4_RULES_FILE}" "${iptables_IPv4_rules_backup_file}" || ExitScript 1 "failed rules backup of file '${IPTABLES_IPV4_RULES_FILE}', not making changes permanent: MODIFICATIONS ARE NOT SAVED"
  fi

  if [ -r "${IPTABLES_IPV6_RULES_FILE}" ]; then
    iptables_IPv6_rules_backup_file="${IPTABLES_IPV6_RULES_FILE}_$(date +%Y%m%d-%H%M%S)"
    WriteInfo "backing up file '${IPTABLES_IPV6_RULES_FILE}' to '${iptables_IPv6_rules_backup_file}' ..."
    cp -p "${IPTABLES_IPV6_RULES_FILE}" "${iptables_IPv6_rules_backup_file}" || ExitScript 1 "failed rules backup of file '${IPTABLES_IPV6_RULES_FILE}', not making changes permanent: MODIFICATIONS ARE NOT SAVED"
  fi

  WriteDebug "running '${IPTABLES_SAVE} > ${IPTABLES_IPV4_RULES_FILE}'"
  ${IPTABLES_SAVE} > "${IPTABLES_IPV4_RULES_FILE}" || ExitScript 1 "failed saving rules to '${IPTABLES_IPV4_RULES_FILE}': MODIFICATIONS ARE NOT SAVED"
  WriteDebug "running '${IP6TABLES_SAVE} > ${IPTABLES_IPV6_RULES_FILE}'"
  ${IP6TABLES_SAVE} > "${IPTABLES_IPV6_RULES_FILE}" || ExitScript 1 "failed saving rules to '${IPTABLES_IPV6_RULES_FILE}': MODIFICATIONS ARE NOT SAVED"
else
  WriteInfo "rules directory '${IPTABLES_DIR}' missing, rules backup skipped"
fi

ExitScript
