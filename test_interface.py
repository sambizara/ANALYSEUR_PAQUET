from scapy.all import IP, TCP
from interface import Application
from packet_analyzer import analyser_paquet


app = Application()


paquet_test = IP(
    src="192.168.1.10",
    dst="8.8.8.8"
) / TCP(
    sport=5000,
    dport=443
)


infos = analyser_paquet(paquet_test)

app.ajouter_paquet(infos)


app.mainloop()