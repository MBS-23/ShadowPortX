"""Port intelligence: well-known port → service map and port-spec resolution.

``COMMON_PORTS`` doubles as the fallback service-name resolver used when protocol
fingerprinting is inconclusive.
"""

from __future__ import annotations

# Security-relevant well-known ports. Not exhaustive, but covers the services the
# fingerprinting and verification engines care about.
COMMON_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "smtp",
    37: "time", 43: "whois", 53: "dns", 67: "dhcp", 69: "tftp", 79: "finger",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    389: "ldap", 427: "svrloc", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 512: "exec", 513: "login", 514: "shell", 515: "printer",
    520: "rip", 523: "db2", 540: "uucp", 548: "afp", 554: "rtsp", 587: "submission",
    623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
    1194: "openvpn", 1352: "lotusnotes", 1433: "ms-sql", 1434: "ms-sql-m",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-ssl", 2379: "etcd", 2483: "oracle-db", 2484: "oracle-db-ssl",
    3000: "http-dev", 3128: "squid-proxy", 3268: "globalcat-ldap", 3306: "mysql",
    3389: "ms-wbt-server", 3690: "svn", 4444: "metasploit", 4505: "salt",
    4506: "salt", 4567: "galera", 4711: "unknown", 4848: "glassfish", 5000: "http-dev",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    5985: "winrm", 5986: "winrm-ssl", 6000: "x11", 6379: "redis", 6443: "kubernetes",
    6514: "syslog-tls", 6660: "irc", 6667: "irc", 7000: "cassandra", 7001: "weblogic",
    7077: "spark", 7199: "cassandra-jmx", 7473: "neo4j-https", 7474: "neo4j",
    7687: "neo4j-bolt", 8000: "http-alt", 8008: "http-alt", 8009: "ajp13",
    8020: "hadoop", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
    8088: "hadoop-yarn", 8089: "splunkd", 8090: "confluence", 8161: "activemq",
    8200: "vault", 8443: "https-alt", 8500: "consul", 8529: "arangodb",
    8686: "jmx", 8880: "websphere", 8888: "http-alt", 9000: "sonarqube",
    9042: "cassandra-cql", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 9418: "git", 9443: "https-alt", 9990: "wildfly",
    9999: "http-alt", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    16379: "redis-cluster", 27017: "mongodb", 27018: "mongodb-shard",
    27019: "mongodb-config", 28017: "mongodb-web", 50000: "sap", 50070: "hadoop-hdfs",
    61616: "activemq", 9091: "transmission", 30000: "unknown",
}

# Nmap-style top ports, ordered by real-world frequency (compact curated list).
_TOP_100 = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
    514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
    8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800,
    106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144,
    7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13,
    1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 6379,
]

_HIGH_VALUE = [
    2375, 2376, 2379, 6443, 8500, 8200, 5601, 9200, 9300, 27017, 6379, 11211, 5984,
    9092, 2181, 15672, 5672, 7474, 7687, 8086, 9000, 8081, 8090, 8161, 50070, 8089,
]


def _top_ports(n: int) -> list[int]:
    ordered = list(dict.fromkeys(_TOP_100 + _HIGH_VALUE + sorted(COMMON_PORTS)))
    return ordered[:n]


def resolve_ports(spec: str | None) -> list[int]:
    """Resolve a port spec into a sorted, de-duplicated list of ports.

    Accepts: ``top100``, ``top1000``, ``all``, ranges (``1-1024``), and comma lists
    (``80,443,8080``), or any combination (``top100,8000-8100``).
    """
    spec = (spec or "top1000").strip().lower()
    ports: set[int] = set()

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        # (bandit B105 false positives below: these are port-spec keywords, not passwords)
        if token == "all":  # nosec B105
            return list(range(1, 65536))
        if token == "top100":  # nosec B105
            ports.update(_top_ports(100))
        elif token == "top1000":  # nosec B105
            ports.update(_top_ports(1000))
            ports.update(range(1, 1025))
        elif "-" in token:
            lo, _, hi = token.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
                ports.update(range(max(1, lo_i), min(65535, hi_i) + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(ports) or _top_ports(1000)


def service_name_for(port: int) -> str | None:
    return COMMON_PORTS.get(port)
