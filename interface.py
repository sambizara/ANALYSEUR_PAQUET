import tkinter as tk
from tkinter import ttk

class Application(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Analyseur de paquets")
        self.geometry("1100x600")
        self.numero_paquet = 1

        self.creer_tableau()

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