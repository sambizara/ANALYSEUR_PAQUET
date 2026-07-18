from scapy.all import sniff
from packet_analyzer import analyser_paquet
import threading


class Capture:

    def __init__(self, interface):

        self.interface = interface
        self.callback = None
        self.actif = False

    def demarrer(self):

        if self.actif:
            return

        self.actif = True

        thread = threading.Thread(
            target=self.capturer,
            daemon=True
        )

        thread.start()

    def capturer(self):

        sniff(
            iface=self.interface,
            prn=self.traiter_paquet,
            store=False,
            stop_filter=lambda x: not self.actif
        )

    def traiter_paquet(self, packet):

        infos = analyser_paquet(packet)

        if self.callback:
            self.callback(infos)

    def arreter(self):

        self.actif = False