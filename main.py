from interface import Application
from capture import Capture
from statistics import Statistics
from dashboard import afficher_dashboard
from filter import Filter


app = Application()

stats = Statistics()

filtre = Filter()

capture = Capture(
    "Qualcomm Atheros AR956x Wireless Network Adapter"
)


def traiter_paquet(infos):

    filtre.protocole = app.combo_protocole.get() or None

    filtre.ip_source = app.entry_source.get() or None

    filtre.ip_destination = app.entry_destination.get() or None

    port = app.entry_port.get()

    if port != "":
        filtre.port = int(port)
    else:
        filtre.port = None

    if filtre.appliquer(infos):

        app.after(
            0,
            lambda: app.ajouter_paquet(infos)
        )

        stats.ajouter_paquet(infos)


capture.callback = traiter_paquet


app.btn_start.config(
    command=capture.demarrer
)

app.btn_stop.config(
    command=capture.arreter
)

app.btn_dashboard.config(
    command=lambda: afficher_dashboard(stats)
)


app.mainloop()