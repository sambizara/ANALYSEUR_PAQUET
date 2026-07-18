import matplotlib.pyplot as plt


def afficher_dashboard(stats):

    plt.figure(figsize=(10,5))


    # graphique protocoles
    plt.subplot(1,2,1)

    protocoles = list(stats.protocoles.keys())
    valeurs = list(stats.protocoles.values())

    plt.pie(
        valeurs,
        labels=protocoles,
        autopct="%1.1f%%"
    )

    plt.title("Répartition des protocoles")


    # informations générales
    plt.subplot(1,2,2)

    infos = [
        f"Paquets : {stats.total_paquets}",
        f"Taille : {stats.taille_totale} octets"
    ]

    plt.axis("off")

    plt.text(
        0.1,
        0.6,
        "\n".join(infos),
        fontsize=15
    )


    plt.suptitle("Dashboard Analyseur Réseau")

    plt.show()