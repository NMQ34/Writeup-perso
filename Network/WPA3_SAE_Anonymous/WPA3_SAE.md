<img src='assets/box.png' alt="Network-Analysis" width="200">

Analyse de Trafic Réseau : Cryptanalyse WPA3-SAE via fuite de masque

> [!NOTE]
> **Note d'éthique** : Ce writeup est volontairement anonymisé et les données sensibles (secret réel, flag final) ont été modifiées. Cette démarche vise à démontrer une méthodologie de résolution sans dégrader l'expérience des autres utilisateurs, conformément aux règles de la plateforme hébergeant l'exercice.

Informations de la Cible

    Nom : WPA3-SAE Cryptanalysis (Anonymized)

    Difficulté : Hard

    Outils : Wireshark, Python3, fastecdsa


1. Introduction

L'objectif de ce challenge est d'analyser une capture réseau Wi-Fi sécurisée par le protocole WPA3-Personal (SAE). Contrairement au WPA2, l'échange Dragonfly utilise des mécanismes de confidentialité persistante (Forward Secrecy) pour empêcher le déchiffrement du trafic à partir du seul mot de passe réseau. Cependant, l'exercice met en scène une compromission logicielle où la valeur brute du masque d'aveuglement éphémère de la station a fuité. Le but est d'exploiter cette fuite pour reconstruire mathématiquement les clés de session et déchiffrer le trafic utilisateur.


2. Analyse des Captures et Extraction des Données

L'analyse débute par l'examen d'un fichier de capture contenant la phase d'authentification complète.

### A. Identification des paramètres de sécurité

En inspectant l'élément d'information RSN (Robust Security Network) des trames de gestion, on identifie l'utilisation de la suite d'authentification SAE (SHA256) (AKM type 8) sur le groupe NIST 19 (courbe elliptique secp256r1 / P-256).

Source et structure de l'échange : https://mrncciew.com/2019/11/29/wpa3-sae-mode/

### B. Collecte des valeurs publiques

Pour mener à bien la reconstruction cryptographique, quatre valeurs clés sont extraites des messages d'engagement (SAE Commit) échangés entre la station (STA) et le point d'accès (AP), notamment au niveau du handshake EAPOL :
- `SCALAR_STA` & `ELEMENT_STA` (Coordonnées du point de la station)
- `SCALAR_AP` & `ELEMENT_AP` (Coordonnées du point de l'AP)


3. Reconstruction Géométrique et Dérivation de la PMK

Dans le protocole Dragonfly, les valeurs publiques d'engagement dépendent d'un secret éphémère $r$ et d'un masque d'aveuglement $m$. Nous disposons ici du masque fuité : `MASK`.

### Étape A : Isolation du Point PWE et du secret éphémère

L'élément public de la station étant défini par $Element = -mask \times PWE$, l'application de l'inverse multiplicatif modulaire du masque par rapport à l'ordre $Q$ de la courbe permet d'isoler le point de mot de passe ($PWE$) d'origine :

$$inv\_mask = mask^{-1} \pmod Q$$

$$PWE = inv\_mask \times (-Element_{\text{STA}})$$

Parallèlement, le secret éphémère privé de la station ($r_{\text{STA}}$) est isolé par la soustraction modulaire du scalaire public :

$$r_{\text{STA}} = (Scalar_{\text{STA}} - mask) \pmod Q$$

Le secret partagé de session (le point elliptique $K$) est alors calculé en reproduisant l'opération Diffie-Hellman :

$$K = r_{\text{STA}} \times (Element_{\text{AP}} + Scalar_{\text{AP}} \times PWE)$$

### Étape B : Script d'extraction de la clé maîtresse (Python)

Conformément aux spécifications de la norme IEEE Std 802.11, l'abscisse du point $K$ ($val_K$) subit une expansion pseudo-aléatoire via SHA256-PRF pour générer un bloc de 64 octets. Les 32 derniers octets constituent la clé maîtresse de paire (PMK).

> [!TIP]
> **Recommandation** : Il est conseillé d'isoler l'exécution dans un environnement virtuel Python pour éviter tout conflit avec les dépendances globales :
> 
> ```bash
> # Création et activation de l'environnement virtuel
> python3 -m venv venv
> source venv/bin/activate
> 
> # Installation de la bibliothèque de courbes elliptiques
> pip install --upgrade pip
> pip install fastecdsa
> ```

```python
import hashlib
import hmac
import struct
from fastecdsa.curve import P256
from fastecdsa.point import Point

P = P256.p
Q = P256.q

# Leaked blinding mask (Anonymized)
MASK = 0x7e8b61a3d902f5c8c2a39df845017e29c0a6b41295f1903be65902187f54c382

# Frame 253 (STA)
SCALAR_STA = 0x8e2019bafcac70b08246c83de7c5e866fea8a670e2381946e889007e4f06595f
ELEMENT_STA_X = 0x41c6fcec65ffbfdb5265484e57f39eb32032e89b553e9c5fcf3217f78d856f34
ELEMENT_STA_Y = 0x7f590353a2c8a6339eea9839bd25377d42b1c2472436dec42c6ab20974ca18d0
Sta_Element = Point(ELEMENT_STA_X, ELEMENT_STA_Y, curve=P256)

# Frame 256 (AP)
SCALAR_AP = 0x88257a2bdb2b30385fbc177ee02155d15ee65341b6dbdcf0a675ea2515d3df13
ELEMENT_AP_X = 0xb47cdcc540885c9251a4873fc336244b786010d990b46b8a4faeb59701c57c48
ELEMENT_AP_Y = 0x5e9565ce1cd5e94e71081706c820234f37829433d29d30570db71228ad4c8265
AP_Element = Point(ELEMENT_AP_X, ELEMENT_AP_Y, curve=P256)

# 1. Exact geometric calculation of PWE and K
inv_mask = pow(MASK, -1, Q)
Sta_Element_Neg = Point(ELEMENT_STA_X, (P - ELEMENT_STA_Y) % P, curve=P256)
PWE_Point = Sta_Element_Neg * inv_mask

r_sta = (SCALAR_STA - MASK) % Q
K_Point = (AP_Element + (PWE_Point * SCALAR_AP)) * r_sta
val_K = K_Point.x.to_bytes(32, 'big')

# 2. Derivation of the keyseed
keyseed = hmac.new(b"\x00" * 32, val_K, hashlib.sha256).digest()

# 3. Construction of the standardized context (order_len = 32 bytes)
context_val = (SCALAR_STA + SCALAR_AP) % Q
context = context_val.to_bytes(32, 'big')

# 4. SHA256-PRF expansion function (IEEE Std 802.11)
def prf_sha256_512(key, label, ctx):
    result = b""
    # 2 iterations of HMAC-SHA256 are needed to obtain 512 bits (64 bytes)
    for i in range(1, 3):
        msg = struct.pack("<H", i) + label + ctx + struct.pack("<H", 512)
        result += hmac.new(key, msg, hashlib.sha256).digest()
    return result

# Key generation
keys = prf_sha256_512(keyseed, b"SAE KCK and PMK", context)
pmk = keys[32:] # The last 32 bytes

print("\n" + "="*60)
print(f"[+] THE SECURE RAW PMK KEY IS GENERATED :")
print(f"-> {pmk.hex()}")
print("="*60)
```

Résultat : La clé PMK brute de session est identifiée.


4. Déchiffrement du Trafic (Trafic WPA3)

La clé PMK obtenue est une clé éphémère propre à cette session spécifique.

### A. Injection de la PMK dans Wireshark

Pour casser le chiffrement des données, la chaîne hexadécimale de 64 caractères de la PMK est importée manuellement dans Wireshark via le menu :
`Preferences > Protocols > IEEE 802.11 > Decryption Keys`.

La clé est déclarée sous le type `wpa-psk` pour indiquer au dissecteur de Wireshark qu'il s'agit du matériau maître brut.

### B. Dérivation de la clé transitoire (PTK)

Une fois la PMK appliquée, Wireshark utilise les paramètres du handshake EAPOL à 4 étapes (4-way handshake) présents dans le fichier de capture pour dériver la clé transitoire (PTK). Les trames de données chiffrées en CCMP basculent instantanément en protocoles clairs (TCP, ICMP, DHCP).


5. Analyse du contenu et Flag

### A. Analyse du flux déchiffré

En utilisant la fonction `Follow > TCP Stream` sur les flux de données réassemblés, la charge utile applicative devient entièrement lisible.

**Analyse finale :**  
Le flag est extrait directement du flux TCP reconstruit. L'interception réussie met en évidence que l'implémentation de la confidentialité persistante du WPA3 dépend de l'étanchéité absolue de ses secrets d'aveuglement : la fuite d'un unique paramètre éphémère local ($mask$) réduit à néant l'ensemble des barrières cryptographiques de l'échange Dragonfly.
