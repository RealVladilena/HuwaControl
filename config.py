import hashlib
import os
import secrets

# ─── PostgreSQL ───────────────────────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST",           "db")
DB_PORT = int(os.getenv("DB_PORT",       "5432"))
DB_NAME = os.getenv("POSTGRES_DB",       "huwacontrol")
DB_USER = os.getenv("POSTGRES_USER",     "huwa")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "huwacontrol")

# ─── Flask ────────────────────────────────────────────────────────────────────
# SECRET_KEY : si non définie, dérivée de POSTGRES_PASSWORD (stable entre
# redémarrages). Définir SECRET_KEY explicitement en production.
_raw_key = os.getenv("SECRET_KEY")
if not _raw_key:
    _raw_key = hashlib.sha256(
        f"huwacontrol-secret-{DB_PASS}".encode()
    ).hexdigest()
SECRET_KEY = _raw_key
DEBUG      = os.getenv("DEBUG", "false").lower() == "true"

# ─── OIDs standards (RFC 1213 / IF-MIB) ──────────────────────────────────────
OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

OID_IF_DESCR  = "1.3.6.1.2.1.2.2.1.2"
OID_IF_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCT = "1.3.6.1.2.1.31.1.1.1.6"   # ifHCInOctets  (64-bit)
OID_IF_OUT_OCT= "1.3.6.1.2.1.31.1.1.1.10"  # ifHCOutOctets (64-bit)
OID_IF_IN_ERR = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERR= "1.3.6.1.2.1.2.2.1.20"
OID_IF_SPEED  = "1.3.6.1.2.1.31.1.1.1.15"  # ifHighSpeed (Mbps)
OID_IF_IN_PKT = "1.3.6.1.2.1.31.1.1.1.7"   # ifHCInUcastPkts  (64-bit)
OID_IF_OUT_PKT= "1.3.6.1.2.1.31.1.1.1.11"  # ifHCOutUcastPkts (64-bit)

# ─── OIDs Huawei spécifiques ─────────────────────────────────────────────────
OID_HW_CPU  = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"
OID_HW_MEM  = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7"
OID_HW_TEMP = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11"

# ─── Table ARP (clients connectés) ───────────────────────────────────────────
OID_ARP_MAC  = "1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress
OID_ARP_TYPE = "1.3.6.1.2.1.4.22.1.4"   # ipNetToMediaType (3=dynamic)

# ─── Huawei WLAN MIB (AR651W) ────────────────────────────────────────────────
OID_WLAN_STA_ENTRY = "1.3.6.1.4.1.2011.6.139.13.3.1.1"  # hwWlanApStaInfoEntry
OID_WLAN_STA_RSSI  = "1.3.6.1.4.1.2011.6.139.13.3.1.1.9"
OID_WLAN_STA_SSID  = "1.3.6.1.4.1.2011.6.139.13.3.1.1.4"

# ─── Table de routage (ipRouteTable — RFC 1213) ───────────────────────────────
OID_ROUTE_DEST    = "1.3.6.1.2.1.4.21.1.1"   # ipRouteDest
OID_ROUTE_MASK    = "1.3.6.1.2.1.4.21.1.11"  # ipRouteMask
OID_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"   # ipRouteNextHop
OID_ROUTE_TYPE    = "1.3.6.1.2.1.4.21.1.8"   # ipRouteType (1=other,2=invalid,3=direct,4=indirect)
OID_ROUTE_METRIC  = "1.3.6.1.2.1.4.21.1.3"   # ipRouteMetric1
OID_ROUTE_IFINDEX = "1.3.6.1.2.1.4.21.1.2"   # ipRouteIfIndex

# ─── Huawei IPSec / IKE VPN MIB (AR series) ──────────────────────────────────
OID_HW_IKE_PEER_TABLE = "1.3.6.1.4.1.2011.6.122.1.3.1"  # hwIKEPeerTable
OID_HW_IKE_SA_TABLE   = "1.3.6.1.4.1.2011.6.122.1.4.1"  # hwIKESATable

# ─── BGP (RFC 1657 standard — fonctionne sur AR) ─────────────────────────────
OID_BGP_PEER_TABLE   = "1.3.6.1.2.1.15.3.1"
OID_BGP_PEER_STATE   = "1.3.6.1.2.1.15.3.1.2"    # 6 = established
OID_BGP_PEER_UPTIME  = "1.3.6.1.2.1.15.3.1.24"   # seconds since established
OID_BGP_PEER_IN_UPD  = "1.3.6.1.2.1.15.3.1.16"
OID_BGP_PEER_OUT_UPD = "1.3.6.1.2.1.15.3.1.17"
OID_BGP_PEER_PREFIXES= "1.3.6.1.2.1.15.3.1.22"   # bgpPeerInTotalMessages (fallback)
# Huawei hwBgp (prefix received)
OID_HW_BGP_PEER      = "1.3.6.1.4.1.2011.5.25.177.1.1.2.1"

# ─── OSPF (RFC 1850 standard) ─────────────────────────────────────────────────
OID_OSPF_NBR_TABLE   = "1.3.6.1.2.1.14.10.1"
OID_OSPF_NBR_IPADDR  = "1.3.6.1.2.1.14.10.1.1"
OID_OSPF_NBR_RTRID   = "1.3.6.1.2.1.14.10.1.3"
OID_OSPF_NBR_STATE   = "1.3.6.1.2.1.14.10.1.6"   # 8 = full
OID_OSPF_NBR_EVENTS  = "1.3.6.1.2.1.14.10.1.9"

# ─── DHCP Server Huawei ───────────────────────────────────────────────────────
OID_HW_DHCP_LEASE    = "1.3.6.1.4.1.2011.6.8.1.5.1"   # hwDhcpServerStatClientLeaseTable
# Colonnes : .1=MAC, .2=IP, .3=type(1=dynamic), .5=ttl_remaining_sec, .9=vrf

# ─── SNMP Trap standard OIDs ─────────────────────────────────────────────────
OID_TRAP_SYSUPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SNMP_TRAP_OID    = "1.3.6.1.6.3.1.1.4.1.0"
OID_TRAP_LINK_DOWN   = "1.3.6.1.6.3.1.1.5.3"
OID_TRAP_LINK_UP     = "1.3.6.1.6.3.1.1.5.4"

# ─── Syslog receiver ─────────────────────────────────────────────────────────
SYSLOG_PORT      = int(os.getenv("SYSLOG_PORT",      "1514"))   # port interne container
SYSLOG_HOST_PORT = int(os.getenv("SYSLOG_HOST_PORT", "514"))    # port exposé (vu par le routeur)
SNMP_TRAP_PORT   = int(os.getenv("SNMP_TRAP_PORT",   "1162"))

# ─── Version ──────────────────────────────────────────────────────────────────
APP_VERSION    = "2.2.0"
APP_BUILD_DATE = "2026-03-19"
