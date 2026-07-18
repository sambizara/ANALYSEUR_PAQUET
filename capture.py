from scapy.all import sniff
from packet_analyzer import analyser_paquet


class Capture:

    def __init__(self, interface):

        self.interface = interface
        self.actif = False
        self.callback = None


    def demarrer(self):

        self.actif = True

        try:

            sniff(
                iface=self.interface,
                prn=self.traiter_paquet,
                store=False
            )

        except KeyboardInterrupt:

            self.actif = False
            raise


    def traiter_paquet(self, paquet):

        infos = analyser_paquet(paquet)

        if self.callback:

            self.callback(infos)


    def arreter(self):

        self.actif = False