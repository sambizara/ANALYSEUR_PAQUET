class Statistics:

    def __init__(self):

        self.total_paquets = 0
        self.taille_totale = 0

        self.protocoles = {}


    def ajouter_paquet(self, infos):

        self.total_paquets += 1

        self.taille_totale += infos["taille"]

        protocole = infos["protocole"]

        if protocole in self.protocoles:

            self.protocoles[protocole] += 1

        else:

            self.protocoles[protocole] = 1



    def afficher(self):

        print("\n========== STATISTIQUES ==========")

        print("Nombre total de paquets :", self.total_paquets)

        print("Taille totale :", self.taille_totale, "octets")


        print("\nProtocoles :")

        for protocole, nombre in self.protocoles.items():

            print(f"{protocole} : {nombre}")

        print("==================================\n")



    # Nouvelle méthode pour le dashboard

    def get_protocoles(self):

        return self.protocoles



    def get_total_paquets(self):

        return self.total_paquets



    def get_taille_totale(self):

        return self.taille_totale