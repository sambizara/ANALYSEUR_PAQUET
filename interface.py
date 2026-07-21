import tkinter as tk
from tkinter import ttk

import threading
from scapy.all import IFACES

from capture import Capture
from filter import Filter


class Application(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Analyseur de paquets réseau")
        self.geometry("1300x650")

        self.numero_paquet = 1
        self.total_paquets = 0
        self.taille_totale = 0
        self.protocoles = {}

        self.capture = None
        self.thread_capture = None
        filtre = Filter()
        self.filtre = filtre

        self.creer_barre_filtres()

        self.btn_start.config(command=self.demarrer_capture)
        self.btn_stop.config(command=self.arreter_capture)

        self.creer_tableau()
        self.creer_barre_etat()

    def creer_barre_filtres(self):

        frame = tk.Frame(self)
        frame.pack(fill="x", padx=10, pady=5)

        tk.Label(frame, text="Interface").grid(row=0, column=0)

        self.interfaces = {}

        liste_interfaces = []

        for iface in IFACES.values():

            nom_affiche = iface.description

            if not nom_affiche:
                nom_affiche = iface.name

            liste_interfaces.append(nom_affiche)
            self.interfaces[nom_affiche] = iface.name

        self.combo_interface = ttk.Combobox(
            frame,
            values=liste_interfaces,
            state="readonly",
            width=35
        )

        self.combo_interface.grid(row=0, column=1, padx=5)

        if self.combo_interface["values"]:
            self.combo_interface.current(0)

        tk.Label(frame, text="Protocole").grid(row=0, column=2)

        self.combo_protocole = ttk.Combobox(
            frame,
            values=[
                "",
                "TCP",
                "UDP",
                "ICMP",
                "DNS",
                "ARP",
                "IPv6",
                "HTTP",
                "HTTPS",
                "FTP",
                "SSH",
                "SMTP",
                "POP3",
                "IMAP",
                "DHCP",
                "SNMP"
            ],
            width=15
        )
        self.combo_protocole.grid(row=0, column=3, padx=5)

        tk.Label(frame, text="IP Source").grid(row=0, column=4)
        self.entry_source = tk.Entry(frame, width=18)
        self.entry_source.grid(row=0, column=5, padx=5)

        tk.Label(frame, text="IP Destination").grid(row=0, column=6)
        self.entry_destination = tk.Entry(frame, width=18)
        self.entry_destination.grid(row=0, column=7, padx=5)

        tk.Label(frame, text="Port").grid(row=0, column=8)
        self.entry_port = tk.Entry(frame, width=10)
        self.entry_port.grid(row=0, column=9, padx=5)

        self.btn_start = tk.Button(
            frame,
            text="Démarrer",
            command=self.demarrer_capture
        )
        self.btn_start.grid(row=0, column=10, padx=5)

        self.btn_stop = tk.Button(frame, text="Arrêter")
        self.btn_stop.grid(row=0, column=11, padx=5)

        self.btn_effacer = tk.Button(
            frame,
            text="Effacer",
            command=self.vider_tableau
        )
        self.btn_effacer.grid(row=0, column=12, padx=5)

        self.btn_filtrer = tk.Button(
            frame,
            text="Appliquer",
            command=self.appliquer_filtre
        )

        self.btn_filtrer.grid(row=0, column=13, padx=5)

        self.btn_dashboard = tk.Button(frame, text="Dashboard")
        self.btn_dashboard.grid(row=0, column=14, padx=5)

    def appliquer_filtre(self):

        self.filtre.protocole = (
            self.combo_protocole.get()
            if self.combo_protocole.get() != ""
            else None
        )

        self.filtre.ip_source = (
            self.entry_source.get()
            if self.entry_source.get() != ""
            else None
        )

        self.filtre.ip_destination = (
            self.entry_destination.get()
            if self.entry_destination.get() != ""
            else None
        )

        port = self.entry_port.get()

        if port != "":
            self.filtre.port = int(port)
        else:
            self.filtre.port = None

    def creer_tableau(self):

        colonnes = (
            "N°",
            "Heure",
            "Source",
            "Mac Src",
            "Mac Dest",
            "Destination",
            "Protocole",
            "Port Src",
            "Port Dest",
            "Taille"
        )

        self.table = ttk.Treeview(
            self,
            columns=colonnes,
            show="headings"
        )

        for col in colonnes:

            self.table.heading(
                col,
                text=col,
                command=lambda c=col: self.trier_colonne(c, False)
            )

            self.table.column(col, width=120)

        self.table.tag_configure("TCP", background="#D6EAF8")
        self.table.tag_configure("UDP", background="#D5F5E3")
        self.table.tag_configure("ICMP", background="#FCF3CF")
        self.table.tag_configure("ARP", background="#FADBD8")
        self.table.tag_configure("DNS", background="#E8DAEF")
        self.table.tag_configure("IPv6", background="#FDEBD0")
        self.table.tag_configure("HTTP", background="#D5F5E3")
        self.table.tag_configure("HTTPS", background="#D6EAF8")
        self.table.tag_configure("Autre", background="white")

        self.table.pack(fill="both", expand=True)

    def creer_barre_etat(self):

        self.status = tk.Label(
            self,
            text="Capture arrêtée",
            anchor="w"
        )

        self.status.pack(fill="x")

    def ajouter_paquet(self, infos):

        protocole = infos["protocole"]

        if protocole not in [
            "TCP",
            "UDP",
            "ICMP",
            "ARP",
            "DNS",
            "IPv6",
            "HTTP",
            "HTTPS"
        ]:
            protocole = "Autre"

        self.table.insert(
            "",
            "end",
            values=(
                self.numero_paquet,
                infos["heure"],
                infos["source"],
                infos["mac_source"],
                infos["mac_destination"],
                infos["destination"],
                infos["protocole"],
                infos["sport"],
                infos["dport"],
                infos["taille"]
            ),
            tags=(protocole,)
        )

        self.numero_paquet += 1

        self.status.config(
            text=f"Capture en cours | {self.numero_paquet-1} paquets"
        )

    def vider_tableau(self):

        for ligne in self.table.get_children():

            self.table.delete(ligne)

        self.numero_paquet = 1

        self.status.config(text="Tableau vidé")

    def reinitialiser(self):

        self.total_paquets = 0
        self.taille_totale = 0
        self.protocoles.clear()

    def recuperer_filtres(self):

        filtres = {}

        protocole = self.combo_protocole.get()

        if protocole != "":
            filtres["protocole"] = protocole

        source = self.entry_source.get()

        if source != "":
            filtres["source"] = source

        destination = self.entry_destination.get()

        if destination != "":
            filtres["destination"] = destination

        port = self.entry_port.get()

        if port != "":

            try:
                filtres["port"] = int(port)

            except ValueError:
                pass

        return filtres

    def trier_colonne(self, colonne, inverse):

        lignes = [
            (self.table.set(item, colonne), item)
            for item in self.table.get_children("")
        ]

        lignes.sort(reverse=inverse)

        for index, (_, item) in enumerate(lignes):

            self.table.move(item, "", index)

        self.table.heading(
            colonne,
            command=lambda: self.trier_colonne(
                colonne,
                not inverse
            )
        )

    def demarrer_capture(self):
        self.appliquer_filtre()

        if self.capture is not None:
            return

        nom_affiche = self.combo_interface.get()

        if nom_affiche == "":
            self.status.config(
                text="Veuillez choisir une interface."
            )
            return

        interface = self.interfaces[nom_affiche]

        self.capture = Capture(interface)

        def callback(infos):
            if self.filtre.appliquer(infos):

                self.after(
                    0,
                    lambda: self.ajouter_paquet(infos)
                )

        self.capture.callback = callback

        self.thread_capture = threading.Thread(
            target=self.capture.demarrer,
            daemon=True
        )

        self.thread_capture.start()

        self.status.config(
            text="Capture en cours..."
        )

    def arreter_capture(self):

        if self.capture is None:
            return

        self.capture.arreter()

        self.capture = None
        self.thread_capture = None

        self.status.config(
            text="Capture arrêtée"
        )