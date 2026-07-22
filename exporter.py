import csv
import json

from scapy.all import wrpcap

class Exporter:

    def exporter_csv(self, paquets, fichier):

        with open(
            fichier,
            mode="w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            champs = [
                "heure",
                "mac_source",
                "mac_destination",
                "source",
                "destination",
                "protocole",
                "sport",
                "dport",
                "taille"
            ]

            writer = csv.DictWriter(
                csvfile,
                fieldnames=champs
            )

            writer.writeheader()

            for paquet in paquets:

                writer.writerow(paquet)


    def exporter_json(self, paquets, fichier):

        with open(
            fichier,
            mode="w",
            encoding="utf-8"
        ) as jsonfile:

            json.dump(
                paquets,
                jsonfile,
                indent=4,
                ensure_ascii=False
            )


    def exporter_pcap(self, paquets, fichier):

        wrpcap(
            fichier,
            paquets
        )