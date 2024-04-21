# Log Analysis Tool
Applicazione Python per l'analisi e la categorizzazione di file di log, con particolare attenzione ai log di connessione SSH. L'applicazione legge un file di log in formato testuale e identifica gli eventi di interesse, come i tentativi di autenticazione falliti. Fornisce anche una visualizzazione grafica delle categorie di log identificate e genera un file di testo che individua gli indirizzi IP sospetti.

# Caratteristiche
Categorizzazione dei log: il programma analizza ogni voce di log e la assegna a una categoria specifica come "Connection closed [preauth]", "Invalid user [preauth]", "Authentication failure [preauth]", ecc. Utilizza espressioni regolari per individuare i modelli di log corrispondenti a ciascuna categoria.

Elaborazione sequenziale: il programma esegue l'analisi dei log in modo sequenziale, processando ogni voce di log una alla volta.

Elaborazione parallela: il programma elabora i log in modo parallelo utilizzando più processi. Divide il file di log in chunk e assegna ciascun chunk a un processo separato per l'elaborazione simultanea, migliorando le prestazioni soprattutto sui sistemi multi-core.

Entrambe le elaborazioni mostrano un grafico a barre per rappresentare la frequenza delle diverse categorie di attività sospette.

Output dei risultati: il programma genera due file di output uguali che contiengono l'elenco degli indirizzi IP sospetti e le categorie di attività associate.

# Dipendenze
Python 3.x
matplotlib (per la visualizzazione dei grafici)
