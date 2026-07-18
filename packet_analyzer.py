from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, DNS, IPv6, Ether, ARP
from protocol_detector import detecter_protocole


def analyser_paquet(packet):

    source = ""
    destination = ""

    sport = ""
    dport = ""

    mac_source = ""
    mac_destination = ""


    # ARP
    if packet.haslayer(ARP):

        source = packet[ARP].psrc
        destination = packet[ARP].pdst


    # IPv4
    elif packet.haslayer(IP):

        source = packet[IP].src
        destination = packet[IP].dst


    # IPv6
    elif packet.haslayer(IPv6):

        source = packet[IPv6].src
        destination = packet[IPv6].dst



    # Ports TCP / UDP
    if packet.haslayer(TCP):

        sport = packet[TCP].sport
        dport = packet[TCP].dport


    elif packet.haslayer(UDP):

        sport = packet[UDP].sport
        dport = packet[UDP].dport



    # MAC
    if packet.haslayer(Ether):

        mac_source = packet[Ether].src
        mac_destination = packet[Ether].dst



    return {

        "heure": datetime.now().strftime("%H:%M:%S"),

        "mac_source": mac_source,

        "mac_destination": mac_destination,

        "source": source,

        "destination": destination,

        "protocole": detecter_protocole(packet),

        "sport": sport,

        "dport": dport,

        "taille": len(packet)

    }