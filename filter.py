class Filter:

    def __init__(self):

        self.protocole = None
        self.ip_source = None
        self.ip_destination = None
        self.port = None


    def appliquer(self, infos):

        # Filtre protocole
        if self.protocole is not None:
            if infos.get("protocole") != self.protocole:
                return False


        # Filtre IP source
        if self.ip_source is not None:
            if infos.get("source") != self.ip_source:
                return False


        # Filtre IP destination
        if self.ip_destination is not None:
            if infos.get("destination") != self.ip_destination:
                return False


        # Filtre port
        if self.port is not None:

            if (
                infos.get("sport") != self.port
                and
                infos.get("dport") != self.port
            ):
                return False


        return True