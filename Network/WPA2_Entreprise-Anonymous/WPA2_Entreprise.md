<img src='assets/box.png' alt="Network-Analysis" width="200">

Analyse de Trafic Réseau : Radius WPA2-Entreprise

> [!NOTE]
> **Note d'éthique** : Ce writeup est volontairement anonymisé et les données sensibles (nom du challenge, secret réel, flag final) ont été modifiées. Cette démarche vise à démontrer une méthodologie de résolution sans dégrader l'expérience des autres utilisateurs, conformément aux règles de la plateforme hébergeant l'exercice.

Informations de la Cible

    Nom : Radius WPA2-Enterprise Analysis (Anonymized)

    Difficulté : Hard

    Outils : Wireshark, Python3, Hexeditor, Rockyou.txt


1. Introduction

L'objectif de ce challenge est d'analyser une capture réseau Wi-Fi sécurisée par le protocole WPA2-Entreprise (802.1X). Contrairement au WPA-Personnel, les clés de chiffrement sont ici distribuées dynamiquement par un serveur RADIUS. Le but est de retrouver le secret partagé (Shared Secret) du service RADIUS pour dériver les clés de session et déchiffrer le trafic utilisateur.


2. Analyse des captures (Trafic RADIUS)

L'analyse débute par un fichier de capture contenant les échanges entre une borne d'accès (NAS) et un serveur RADIUS.

### A. Identification du protocole

En filtrant sur le protocole `radius`, on observe des paquets `Access-Request` et `Access-Accept`. Ces paquets contiennent un attribut crucial : le `Message-Authenticator`.

### B. Vulnérabilité du Message-Authenticator

Le `Message-Authenticator` est un hash HMAC-MD5 calculé à partir du contenu du paquet et d'un Shared Secret. Si ce secret est faible, il est possible de réaliser une attaque par dictionnaire hors-ligne.


3. Extraction et Brute-force du Secret

Pour retrouver le secret, nous devons isoler un paquet et tenter de recalculer un hash identique au `Message-Authenticator` capturé.

### Étape A : Préparation du paquet brut

- Exportation d'un paquet `Access-Request` en format brut via Wireshark.
    (Radius Protocol > Export Packet Bytes > file.bin)
- Utilisation d'un éditeur hexadécimal (Hexeditor) pour remplacer les 16 octets du champ `Message-Authenticator` par des zéros (`00`) dans notre (file.bin). Cette étape est nécessaire pour simuler l'état du paquet avant sa signature.

### Étape B : Script de Brute-force (Python)

Nous utilisons un script Python pour itérer sur la liste `rockyou.txt` afin de retrouver le secret (Anonymized).

source : https://medium.com/@abdoemam_34814/wpa2-enterprise-assessment-and-hardening-for-security-teams-c572eaeceb5f

```python
import hmac
import hashlib

# Path to the rockyou.txt wordlist
rockyou_path = "/usr/share/wordlists/rockyou.txt"
# Path to the packet file with zeroed-out Message-Authenticator
packet_file = "file.bin"
# Original Message-Authenticator (hex format from last Access-Request packet)
original_message_authenticator = "55dd8bbc1894d9e14c0b24c711ffcdf5"

# Function to calculate HMAC-MD5
def calculate_message_authenticator(shared_secret, packet):
    return hmac.new(shared_secret, packet, hashlib.md5).hexdigest()

# Brute-force function against rockyou.txt
def brute_force_shared_secret():
    with open(packet_file, "rb") as f:
        packet_data = f.read()
        try:
            with open(rockyou_path, "r", encoding="utf-8", errors="ignore") as pwd_file:
                for line in pwd_file:
                    password = line.strip().encode("utf-8")
                    calculated_authenticator = calculate_message_authenticator(password, packet_data)
                    if calculated_authenticator == original_message_authenticator:
                        print(f"[+] Shared Secret Found: {password.decode('utf-8')}")
                        return
        except Exception as e:
            print(f"[-] Error reading {rockyou_path}: {e}")
    print("[!] Shared secret not found in rockyou.txt.")

# Run the brute-force function
brute_force_shared_secret()
```

Résultat : Le secret partagé est identifié (ex: `p4ssw0rd`).


4. Déchiffrement du Trafic (Trafic WPA2)

Une fois le secret RADIUS obtenu, nous pouvons l'utiliser dans Wireshark (Preferences > Protocols > RADIUS) pour déchiffrer les attributs du paquet `Access-Accept`.

### A. Récupération des clés MPPE

Le serveur RADIUS transmet à la borne les clés de session de l'utilisateur via les attributs :
- `MS-MPPE-Recv-Key`
- `MS-MPPE-Send-Key`

Ces clés sont la base de la PMK (Pairwise Master Key) nécessaire pour déchiffrer le trafic Wi-Fi WPA2.

### B. Injection de la clé dans le flux Wi-Fi

Dans le second fichier de capture (contenant le trafic WPA2 chiffré), nous configurons Wireshark (Protocols > IEEE 802.11) en ajoutant la `MS-MPPE-Recv-Key` comme clé de déchiffrement (type WPA-PSK).


5. Analyse du contenu et Flag

Grâce à la clé de session, le trafic utilisateur n'est plus chiffré. En analysant les flux déchiffrés, nous remarquons des communications en clair (TCP/HTTP) là où il n'y avait précédemment que des trames 802.11 illisibles.

En utilisant la fonction `Follow > TCP Stream` sur un flux dirigé vers un port spécifique, nous accédons au contenu des échanges de l'utilisateur.

**Analyse finale :**  
Le flag est récupéré directement dans le corps d'une communication TCP. Le fait que le flag soit visible en clair démontre une absence de chiffrement de couche applicative (ex: pas de HTTPS), rendant les données vulnérables dès lors que le chiffrement de la couche transport (Wi-Fi) est brisé.
