# CertificateAnalysis Masterthesis

# Echtzeitbasierte Netzwerkdatenanalyse zur Ermittlung verwendeter Root Zertifikate

# Vorarbeiten/Nuggets/externe Abhängigkeiten
pthread
pcappluplus
matplotplusplus
openssl


Fragen:
	Zertifikatsspeicher von Windows enthält andere zertifikate als in Browser (Chrome/Firefox)
	Domain/IP muss noch irgendwo mitgespeichert werden um Springer aufzudecken und eventuell um den CAA record festzustellen
	Verfäschlung des ergebnisses der häufigkeit der verwendeten Root CAs aufgrund von gesehenen Verbindungs ende flags jedoch erneute kommunikation
		Ablauf:
		- client baut verbindung auf
		- server sendet hello und certificate
		- client beendet die verbindung (FIN set)
		- encrypted alert vom server
		- reset verbindung vom client

