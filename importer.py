import csv
import json

from scapy.all import rdpcap


class Importer:

    def importer_pcap(self, chemin):

        return rdpcap(chemin)


    def importer_csv(self, chemin):

        paquets = []

        with open(
            chemin,
            newline="",
            encoding="utf-8"
        ) as fichier:

            lecteur = csv.DictReader(fichier)

            for ligne in lecteur:

                paquets.append(ligne)

        return paquets


    def importer_json(self, chemin):

        with open(
            chemin,
            "r",
            encoding="utf-8"
        ) as fichier:

            return json.load(fichier)
