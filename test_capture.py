from capture import Capture
from statistics import Statistics
from dashboard import afficher_dashboard
from filter import Filter


stats = Statistics()

filtre = Filter()

# Test du filtrage
filtre.protocole = "UDP"



def afficher_infos(infos):

    if filtre.appliquer(infos):

        print(infos)

        stats.ajouter_paquet(infos)



capture = Capture(
    "Qualcomm Atheros AR956x Wireless Network Adapter"
)

capture.callback = afficher_infos


try:

    capture.demarrer()

finally:

    print("\nArrêt de la capture...")

    stats.afficher()

    afficher_dashboard(stats)