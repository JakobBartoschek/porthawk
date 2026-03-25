"""Port-to-service mapping and risk scoring.

Hardcoded data, no I/O, no async. Intentionally boring.
Source: IANA service-names-port-numbers, filtered to ports that matter in practice.
"""

from enum import Enum

from pydantic import BaseModel


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"  # open but not inherently dangerous


class ServiceInfo(BaseModel):
    """Everything we know about a port from the static database."""

    port: int
    protocol: str
    service_name: str
    description: str
    risk_level: RiskLevel | None = None


# Ports that are HIGH risk when open to the internet — no argument.
# Telnet, SMB, RDP, old mail protocols — these are the hits in every pentest report.
_HIGH_RISK_PORTS = frozenset(
    {
        21,  # FTP — cleartext auth, anonymous login disasters
        23,  # Telnet — cleartext everything, should be dead
        25,  # SMTP open relay — spammer paradise if misconfigured
        53,  # DNS — zone transfer is HIGH, normal query is INFO
        69,  # TFTP — no auth, unauthenticated file grab
        110,  # POP3 — cleartext email auth
        111,  # RPC portmapper — classic pivoting vector
        119,  # NNTP — rarely needed, often forgotten
        135,  # MSRPC — Windows exploitation starting point
        137,  # NetBIOS Name Service — SMB recon
        138,  # NetBIOS Datagram — SMB recon
        139,  # NetBIOS Session — SMB without TLS
        143,  # IMAP — cleartext mail auth
        161,  # SNMP — community string auth is basically no auth
        389,  # LDAP — cleartext directory queries
        445,  # SMB — EternalBlue, WannaCry, every Windows exploit ever
        512,  # rexec — no auth on old Unix
        513,  # rlogin — no auth on old Unix
        514,  # rsh — no auth, extremely old, shouldn't exist
        1433,  # MSSQL — DB exposed to internet = bad day
        1521,  # Oracle DB — same problem
        2049,  # NFS — world-readable exports are a thing
        3389,  # RDP — ransomware gangs love this port
        4444,  # Metasploit default shell — something is wrong if this is open
        5900,  # VNC — cleartext or weak auth depending on version
        6379,  # Redis — no auth by default, RCE via config set
        27017,  # MongoDB — no auth by default (older versions), data breach classic
    }
)

# MEDIUM risk — legitimate services, but exposure to internet needs justification
_MEDIUM_RISK_PORTS = frozenset(
    {
        22,  # SSH — secure but brute-forced constantly
        3306,  # MySQL — should never be internet-facing
        5432,  # PostgreSQL — same as MySQL
        8080,  # HTTP alt — usually a dev server someone forgot to close
        8443,  # HTTPS alt — fine for internal, suspicious on internet
        1080,  # SOCKS proxy — might be an open proxy
        3128,  # Squid proxy — might be an open proxy
        5000,  # Flask/Docker — dev server exposed
        5001,  # alt dev server port
        8888,  # Jupyter Notebook — if this is open on internet, someone has a bad day
        9200,  # Elasticsearch — another "no auth by default" classic
        9300,  # Elasticsearch cluster — ditto
        11211,  # Memcached — no auth, UDP amplification DDoS vector
        27018,  # MongoDB shard — same auth issues as 27017
        28017,  # MongoDB web interface — definitely shouldn't be public
    }
)

# LOW risk — open and expected, not inherently dangerous
_LOW_RISK_PORTS = frozenset(
    {
        80,  # HTTP — cleartext but ubiquitous; low risk, but redirect to HTTPS
        443,  # HTTPS — expected, just make sure the cert is valid
        465,  # SMTPS — encrypted SMTP
        587,  # SMTP submission — email sending, auth required
        993,  # IMAPS — encrypted IMAP
        995,  # POP3S — encrypted POP3
        8443,  # HTTPS alt — depending on context, could be MEDIUM
        9443,  # HTTPS alt
    }
)

# Main service database — top ~200 ports that show up in real-world scans.
# (tcp, udp) tuples where the protocol matters. Single string = same for both.
_PORT_DB: dict[int, dict[str, str]] = {
    # Well-known ports (0–1023)
    1: {"name": "tcpmux", "desc": "TCP Port Service Multiplexer"},
    7: {"name": "echo", "desc": "Echo Protocol"},
    9: {"name": "discard", "desc": "Discard Protocol"},
    13: {"name": "daytime", "desc": "Daytime Protocol"},
    17: {"name": "qotd", "desc": "Quote of the Day"},
    19: {"name": "chargen", "desc": "Character Generator — DDoS amplification vector"},
    20: {"name": "ftp-data", "desc": "FTP Data Transfer"},
    21: {"name": "ftp", "desc": "File Transfer Protocol — cleartext auth"},
    22: {"name": "ssh", "desc": "Secure Shell"},
    23: {"name": "telnet", "desc": "Telnet — cleartext, should be extinct"},
    25: {"name": "smtp", "desc": "Simple Mail Transfer Protocol"},
    37: {"name": "time", "desc": "Time Protocol"},
    43: {"name": "whois", "desc": "WHOIS Protocol"},
    49: {"name": "tacacs", "desc": "TACACS — terminal access controller"},
    53: {"name": "dns", "desc": "Domain Name System"},
    67: {"name": "dhcps", "desc": "DHCP Server"},
    68: {"name": "dhcpc", "desc": "DHCP Client"},
    69: {"name": "tftp", "desc": "Trivial File Transfer — no auth"},
    70: {"name": "gopher", "desc": "Gopher Protocol — 1993 called"},
    79: {"name": "finger", "desc": "Finger Protocol — user enumeration"},
    80: {"name": "http", "desc": "HTTP — cleartext web"},
    81: {"name": "http-alt", "desc": "HTTP alternate"},
    88: {"name": "kerberos", "desc": "Kerberos Authentication"},
    102: {"name": "iso-tsap", "desc": "ISO Transport Class 0"},
    110: {"name": "pop3", "desc": "Post Office Protocol v3 — cleartext email"},
    111: {"name": "rpcbind", "desc": "Remote Procedure Call portmapper"},
    113: {"name": "ident", "desc": "Identification Protocol"},
    119: {"name": "nntp", "desc": "Network News Transfer Protocol"},
    123: {"name": "ntp", "desc": "Network Time Protocol — UDP amplification DDoS"},
    135: {"name": "msrpc", "desc": "Microsoft RPC — Windows exploitation entry point"},
    137: {"name": "netbios-ns", "desc": "NetBIOS Name Service"},
    138: {"name": "netbios-dgm", "desc": "NetBIOS Datagram Service"},
    139: {"name": "netbios-ssn", "desc": "NetBIOS Session Service"},
    143: {"name": "imap", "desc": "Internet Message Access Protocol — cleartext"},
    161: {"name": "snmp", "desc": "SNMP — community string = basically no auth"},
    162: {"name": "snmptrap", "desc": "SNMP Trap"},
    179: {"name": "bgp", "desc": "Border Gateway Protocol"},
    194: {"name": "irc", "desc": "Internet Relay Chat"},
    220: {"name": "imap3", "desc": "IMAP version 3"},
    264: {"name": "bgmp", "desc": "Border Gateway Multicast Protocol"},
    389: {"name": "ldap", "desc": "Lightweight Directory Access Protocol — cleartext"},
    443: {"name": "https", "desc": "HTTP over TLS"},
    444: {"name": "snpp", "desc": "Simple Network Paging Protocol"},
    445: {"name": "microsoft-ds", "desc": "SMB over TCP — EternalBlue port"},
    464: {"name": "kpasswd", "desc": "Kerberos Change/Set Password"},
    465: {"name": "smtps", "desc": "SMTP over TLS"},
    500: {"name": "isakmp", "desc": "Internet Security Association and Key Management"},
    512: {"name": "exec", "desc": "rexec — Remote Process Execution, no auth"},
    513: {"name": "login", "desc": "rlogin — Remote Login, no auth"},
    514: {"name": "shell", "desc": "rsh — Remote Shell, no auth"},
    515: {"name": "printer", "desc": "Line Printer Daemon"},
    520: {"name": "rip", "desc": "Routing Information Protocol"},
    521: {"name": "ripng", "desc": "RIP for IPv6"},
    540: {"name": "uucp", "desc": "Unix-to-Unix Copy Protocol"},
    543: {"name": "klogin", "desc": "Kerberos Login"},
    544: {"name": "kshell", "desc": "Kerberos Shell"},
    587: {"name": "submission", "desc": "Email Message Submission"},
    631: {"name": "ipp", "desc": "Internet Printing Protocol"},
    636: {"name": "ldaps", "desc": "LDAP over TLS"},
    646: {"name": "ldp", "desc": "Label Distribution Protocol"},
    691: {"name": "msexch-routing", "desc": "MS Exchange Routing"},
    694: {"name": "ha-cluster", "desc": "High Availability Clustering"},
    749: {"name": "kerberos-adm", "desc": "Kerberos Administration"},
    873: {"name": "rsync", "desc": "rsync file sync — check for anonymous access"},
    902: {"name": "vmware-authd", "desc": "VMware vSphere Authentication"},
    989: {"name": "ftps-data", "desc": "FTP Data over TLS"},
    990: {"name": "ftps", "desc": "FTP over TLS"},
    992: {"name": "telnets", "desc": "Telnet over TLS (yes, really)"},
    993: {"name": "imaps", "desc": "IMAP over TLS"},
    995: {"name": "pop3s", "desc": "POP3 over TLS"},
    # Registered ports (1024–49151)
    1080: {"name": "socks", "desc": "SOCKS Proxy — check for open proxy"},
    1194: {"name": "openvpn", "desc": "OpenVPN"},
    1433: {"name": "ms-sql-s", "desc": "Microsoft SQL Server"},
    1434: {"name": "ms-sql-m", "desc": "Microsoft SQL Server Monitor — UDP"},
    1521: {"name": "oracle", "desc": "Oracle Database"},
    1723: {"name": "pptp", "desc": "Point-to-Point Tunneling Protocol"},
    1883: {"name": "mqtt", "desc": "MQTT — IoT messaging, check for no-auth broker"},
    1900: {"name": "upnp", "desc": "Universal Plug and Play — classic home router vuln"},
    2049: {"name": "nfs", "desc": "Network File System — world-readable exports"},
    2082: {"name": "cpanel", "desc": "cPanel"},
    2083: {"name": "cpanels", "desc": "cPanel over TLS"},
    2086: {"name": "whm", "desc": "WebHost Manager"},
    2087: {"name": "whms", "desc": "WebHost Manager over TLS"},
    2121: {"name": "ftp-alt", "desc": "FTP alternate"},
    2181: {"name": "zookeeper", "desc": "Apache ZooKeeper — no auth by default"},
    2222: {"name": "ssh-alt", "desc": "SSH alternate — security through obscurity"},
    2375: {"name": "docker", "desc": "Docker daemon (unencrypted) — critical if exposed"},
    2376: {"name": "docker-tls", "desc": "Docker daemon over TLS"},
    2379: {"name": "etcd-client", "desc": "etcd client — Kubernetes secrets exposure risk"},
    2380: {"name": "etcd-peer", "desc": "etcd peer"},
    3000: {"name": "http-dev", "desc": "HTTP dev server (Node.js, Rails, etc.)"},
    3128: {"name": "squid", "desc": "Squid HTTP Proxy"},
    3260: {"name": "iscsi", "desc": "iSCSI target"},
    3306: {"name": "mysql", "desc": "MySQL Database"},
    3389: {"name": "rdp", "desc": "Remote Desktop Protocol — ransomware entry point"},
    3690: {"name": "svn", "desc": "Subversion"},
    4000: {"name": "http-dev", "desc": "HTTP dev server"},
    4243: {"name": "docker-alt", "desc": "Docker alternate API port"},
    4444: {"name": "krb524", "desc": "Metasploit default shell — why is this open?"},
    4500: {"name": "ipsec-nat", "desc": "IPsec NAT traversal"},
    4848: {"name": "appserv-http", "desc": "GlassFish admin console"},
    5000: {"name": "upnp-http", "desc": "Flask/UPnP/Docker Registry default"},
    5001: {"name": "commplex-link", "desc": "HTTP alt / Docker Registry TLS"},
    5060: {"name": "sip", "desc": "Session Initiation Protocol"},
    5061: {"name": "sips", "desc": "SIP over TLS"},
    5432: {"name": "postgresql", "desc": "PostgreSQL Database"},
    5601: {"name": "kibana", "desc": "Kibana — Elasticsearch UI, check auth"},
    5672: {"name": "amqp", "desc": "Advanced Message Queuing Protocol (RabbitMQ)"},
    5900: {"name": "vnc", "desc": "Virtual Network Computing — weak auth issues"},
    5985: {"name": "winrm-http", "desc": "Windows Remote Management over HTTP"},
    5986: {"name": "winrm-https", "desc": "Windows Remote Management over HTTPS"},
    6379: {"name": "redis", "desc": "Redis — no auth by default, RCE via SLAVEOF"},
    6443: {"name": "kubernetes-api", "desc": "Kubernetes API server"},
    6667: {"name": "irc", "desc": "Internet Relay Chat"},
    7000: {"name": "afs3-fileserver", "desc": "Cassandra inter-node / AFS"},
    7001: {"name": "afs3-callback", "desc": "WebLogic HTTP / AFS callback"},
    7002: {"name": "afs3-prserver", "desc": "WebLogic HTTPS"},
    7474: {"name": "neo4j", "desc": "Neo4j graph database HTTP"},
    8000: {"name": "http-alt", "desc": "HTTP alternate / Django dev"},
    8008: {"name": "http-alt", "desc": "HTTP alternate"},
    8080: {"name": "http-proxy", "desc": "HTTP proxy / Tomcat / dev server"},
    8081: {"name": "blackice-icecap", "desc": "HTTP alternate"},
    8088: {"name": "radan-http", "desc": "HTTP alternate / YARN ResourceManager"},
    8089: {"name": "http-alt", "desc": "HTTP alternate"},
    8161: {"name": "activemq", "desc": "ActiveMQ admin console"},
    8443: {"name": "https-alt", "desc": "HTTPS alternate"},
    8888: {"name": "http-alt", "desc": "HTTP alternate / Jupyter Notebook"},
    9000: {"name": "cslistener", "desc": "PHP-FPM / SonarQube"},
    9001: {"name": "tor-orport", "desc": "Tor OR port / Supervisor"},
    9042: {"name": "cassandra", "desc": "Cassandra CQL native transport"},
    9090: {"name": "zeus-admin", "desc": "Prometheus / WebSM"},
    9091: {"name": "xmltec-xmlmail", "desc": "Transmission BitTorrent"},
    9092: {"name": "kafka", "desc": "Apache Kafka broker — check SASL config"},
    9200: {"name": "elasticsearch", "desc": "Elasticsearch HTTP — no auth default (old versions)"},
    9300: {"name": "elasticsearch-cluster", "desc": "Elasticsearch cluster transport"},
    9418: {"name": "git", "desc": "Git protocol — check for anonymous push"},
    10000: {"name": "webmin", "desc": "Webmin admin panel"},
    10250: {"name": "kubelet", "desc": "Kubernetes kubelet API — pod exec via unauthenticated"},
    11211: {"name": "memcache", "desc": "Memcached — no auth, UDP amplification"},
    15672: {"name": "rabbitmq-mgmt", "desc": "RabbitMQ Management UI"},
    16379: {"name": "redis-sentinel", "desc": "Redis Sentinel"},
    16443: {"name": "microk8s-api", "desc": "MicroK8s API"},
    27017: {"name": "mongodb", "desc": "MongoDB — no auth by default (older versions)"},
    27018: {"name": "mongodb-shard", "desc": "MongoDB Shard Server"},
    27019: {"name": "mongodb-config", "desc": "MongoDB Config Server"},
    28017: {"name": "mongodb-web", "desc": "MongoDB Web Interface"},
    50000: {"name": "ibm-db2", "desc": "IBM DB2"},
    50070: {"name": "hadoop-hdfs", "desc": "Hadoop HDFS NameNode"},
    61616: {"name": "activemq-broker", "desc": "ActiveMQ broker"},
    65535: {"name": "unknown", "desc": "Max port — sometimes used for evasion"},
}


def _determine_risk(port: int) -> RiskLevel | None:
    """Map a port number to its risk level. Returns None for unknown ports."""
    if port in _HIGH_RISK_PORTS:
        return RiskLevel.HIGH
    if port in _MEDIUM_RISK_PORTS:
        return RiskLevel.MEDIUM
    if port in _LOW_RISK_PORTS:
        return RiskLevel.LOW
    return RiskLevel.INFO


def get_service(port: int, protocol: str = "tcp") -> ServiceInfo:
    """Look up a port in the service database.

    Unknown ports get a generic 'unknown' entry — we never return None.
    Protocol is carried through but doesn't currently affect lookup (v0.1.0 limitation).

    Args:
        port: Port number (1–65535).
        protocol: 'tcp' or 'udp'.

    Returns:
        ServiceInfo with name, description, and risk level.
    """
    entry = _PORT_DB.get(port)

    if entry is None:
        return ServiceInfo(
            port=port,
            protocol=protocol,
            service_name="unknown",
            description="No entry in service database",
            risk_level=None,
        )

    return ServiceInfo(
        port=port,
        protocol=protocol,
        service_name=entry["name"],
        description=entry["desc"],
        risk_level=_determine_risk(port),
    )


def get_top_ports(n: int) -> list[int]:
    """Return the top N most commonly scanned ports, sorted by frequency.

    Order is based on typical security scan priority, not IANA assignment order.
    This is the list that nmap uses internally, approximately.

    Args:
        n: Number of ports to return.

    Returns:
        List of port numbers, up to n entries.
    """
    # Ordered by scan priority — common services and frequent vuln targets first
    top_ports = [
        80,
        443,
        22,
        21,
        25,
        3389,
        110,
        445,
        139,
        143,
        53,
        135,
        3306,
        8080,
        1723,
        111,
        995,
        993,
        587,
        23,
        8443,
        8888,
        6379,
        27017,
        5432,
        1433,
        5900,
        2049,
        389,
        161,
        3128,
        1080,
        5000,
        8000,
        9200,
        11211,
        2375,
        10250,
        9092,
        2181,
        6443,
        5672,
        5601,
        9090,
        4444,
        9300,
        27018,
        7001,
        9000,
        9042,
        4848,
        8161,
        15672,
        61616,
        50000,
        50070,
        28017,
        27019,
        16379,
        10000,
        8081,
        8088,
        8089,
        7000,
        7474,
        9418,
        9001,
        5061,
        5060,
        5001,
        4500,
        4243,
        4000,
        3690,
        3260,
        2380,
        2379,
        2376,
        2222,
        2121,
        2087,
        2086,
        2083,
        2082,
        1900,
        1883,
        1521,
        1434,
        1194,
        1027,
        902,
        873,
        749,
        694,
        646,
        636,
        631,
        544,
        543,
        540,
    ]
    # Pad with remaining _PORT_DB keys if we need more than the priority list covers
    remaining = [p for p in sorted(_PORT_DB.keys()) if p not in top_ports]
    all_ports = top_ports + remaining
    return all_ports[:n]
