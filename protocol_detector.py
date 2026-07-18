from scapy.all import TCP, UDP, ICMP, DNS, ARP, IPv6,  GRE

PORT_SERVICES = {

    # Web
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Proxy",

    # Transfert de fichiers
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    69: "TFTP",

    # Messagerie
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",

    # DNS / Réseau
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-Trap",

    # Bases de données
    1433: "SQL-Server",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",

    # Administration distante
    23: "TELNET",
    3389: "RDP",
    5900: "VNC",

    # Jeux / applications courantes
    25565: "Minecraft",
    5060: "SIP",

    # Autres
    445: "SMB",
    139: "NetBIOS",
    514: "Syslog"

}
def detecter_service(port):

    return PORT_SERVICES.get(
        port,
        "Inconnu"
    )



def detecter_protocole(packet):


    if packet.haslayer(ARP):
        return "ARP"
    
    if packet.haslayer(IPv6):
        return "IPv6" 
    
    if packet.haslayer(DNS):
        return "DNS"
    
    if packet.haslayer(TCP):

        sport = packet[TCP].sport
        dport = packet[TCP].dport


        service = detecter_service(dport)

        if service != "Inconnu":
            return service

        service = detecter_service(sport)

        if service != "Inconnu":
            return service  
        
        return "TCP"

    if packet.haslayer(UDP):

        sport = packet[UDP].sport
        dport = packet[UDP].dport


        service = detecter_service(dport)

        if service != "Inconnu":
            return service


        service = detecter_service(sport)

        if service != "Inconnu":
            return service

   
        return "UDP"


    if packet.haslayer(ICMP):
        return "ICMP"


    if packet.haslayer(GRE):
        return "GRE"

    return "Autre"