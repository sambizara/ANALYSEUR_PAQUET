import tkinter as tk
from tkinter import ttk


class Application(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Analyseur de paquets réseau")
        self.geometry("1300x650")

        self.numero_paquet = 1

        self.creer_barre_filtres()
        self.creer_tableau()

    def creer_barre_filtres(self):

        frame = tk.Frame(self)
        frame.pack(fill="x", padx=10, pady=5)

        tk.Label(frame, text="Protocole").grid(row=0, column=0)

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

        self.combo_protocole.grid(row=0, column=1, padx=5)

        tk.Label(frame, text="IP Source").grid(row=0, column=2)

        self.entry_source = tk.Entry(frame, width=18)
        self.entry_source.grid(row=0, column=3, padx=5)

        tk.Label(frame, text="IP Destination").grid(row=0, column=4)

        self.entry_destination = tk.Entry(frame, width=18)
        self.entry_destination.grid(row=0, column=5, padx=5)

        tk.Label(frame, text="Port").grid(row=0, column=6)

        self.entry_port = tk.Entry(frame, width=10)
        self.entry_port.grid(row=0, column=7, padx=5)

        self.btn_start = tk.Button(frame, text="Démarrer")
        self.btn_start.grid(row=0, column=8, padx=10)

        self.btn_stop = tk.Button(frame, text="Arrêter")
        self.btn_stop.grid(row=0, column=9)

        self.btn_dashboard = tk.Button(frame, text="Dashboard")
        self.btn_dashboard.grid(row=0, column=10, padx=10)

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
            self.table.heading(col, text=col)
            self.table.column(col, width=120)

        self.table.pack(fill="both", expand=True)

    def ajouter_paquet(self, infos):

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
            )
        )

        self.numero_paquet += 1