## 1. Règles de Sécurité Générales

### 1.1 Détection de secrets en clair

#### Objectif
Détecter les secrets, clés, mots de passe et tokens stockés directement dans le code source.

#### Règles de détection

| ID Règle | Description | Sévérité |
|----------|-------------|----------|
| **SEC-001** | Clé cryptographique codée en dur | CRITIQUE |
| **SEC-002** | Mot de passe en clair dans le code | CRITIQUE |
| **SEC-003** | Token d'API en clair | CRITIQUE |
| **SEC-004** | Certificat ou clé privée dans le code | CRITIQUE |
| **SEC-005** | Connection string avec credentials | ÉLEVÉ |

#### Patterns de détection Python

```python
# ❌ CRITIQUE - Clé cryptographique codée en dur
SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
AES_KEY = b'sixteen byte key'
API_KEY = "sk-proj-1234567890abcdef"

# ❌ CRITIQUE - Mot de passe en clair
PASSWORD = "mySecretPassword123"
db_password = "admin123"

# ❌ CRITIQUE - Token en clair
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnop"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ❌ ÉLEVÉ - Connection string
DATABASE_URL = "postgresql://user:password@localhost/db"
MONGODB_URI = "mongodb://admin:pass123@localhost:27017"

# ✅ CONFORME - Utilisation de variables d'environnement
import os
SECRET_KEY = os.getenv('SECRET_KEY')
API_KEY = os.getenv('API_KEY')

# ✅ CONFORME - Utilisation de gestionnaires de secrets
from azure.keyvault.secrets import SecretClient
secret = client.get_secret("database-password")
```

---

### 1.2 Détection d'algorithmes faibles ou obsolètes

#### Objectif
Identifier l'utilisation d'algorithmes cryptographiques considérés comme faibles, cassés ou obsolètes.

#### Règles de détection

| ID Règle | Description | Sévérité | Référence ANSSI |
|----------|-------------|----------|-----------------|
| **ALGO-001** | Utilisation de MD5 | CRITIQUE | Section 2.2 |
| **ALGO-002** | Utilisation de SHA-1 | CRITIQUE | Section 2.2 |
| **ALGO-003** | Utilisation de DES | CRITIQUE | Section 2.1 |
| **ALGO-004** | Utilisation de RC4 | CRITIQUE | Obsolète |
| **ALGO-005** | Utilisation de modes ECB | ÉLEVÉ | Section 2.1.2 |
| **ALGO-006** | Triple DES avec clé < 112 bits | ÉLEVÉ | RègleCléSym-1 |
| **ALGO-007** | Chiffrement sans authentification | MOYEN | Best Practice |

#### Exemples de détection Python

```python
# ❌ CRITIQUE - MD5 (cassé)
import hashlib
hash_md5 = hashlib.md5()
hash_md5 = hashlib.md5(data)

from Crypto.Hash import MD5
h = MD5.new()

# ❌ CRITIQUE - SHA-1 (vulnérable aux collisions)
import hashlib
hash_sha1 = hashlib.sha1()
hash_sha1 = hashlib.sha1(data)

from Crypto.Hash import SHA1
h = SHA1.new()

# ❌ CRITIQUE - DES (clé trop courte)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC)

# ❌ CRITIQUE - RC4 (complètement cassé)
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)

# ❌ ÉLEVÉ - Mode ECB (ne masque pas les patterns)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# ⚠️ MOYEN - Chiffrement sans authentification (manque d'intégrité)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)
# Pas de MAC/HMAC pour vérifier l'intégrité

# ✅ CONFORME - SHA-256
import hashlib
hash_obj = hashlib.sha256()
hash_obj = hashlib.sha256(data)

# ✅ CONFORME - AES avec mode authentifié
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# ✅ CONFORME - ChaCha20-Poly1305
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
cipher = ChaCha20Poly1305(key)
ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
```

---

### 1.3 Détection de configurations dangereuses

#### Objectif
Identifier les configurations cryptographiques risquées même avec des algorithmes corrects.

#### Règles de détection

| ID Règle | Description | Sévérité |
|----------|-------------|----------|
| **CONFIG-001** | IV/Nonce réutilisé ou prévisible | CRITIQUE |
| **CONFIG-002** | Salt manquant pour dérivation de clé | ÉLEVÉ |
| **CONFIG-003** | Nombre d'itérations insuffisant (PBKDF2) | ÉLEVÉ |
| **CONFIG-004** | Vérification de certificat SSL désactivée | CRITIQUE |
| **CONFIG-005** | Version TLS obsolète | ÉLEVÉ |
| **CONFIG-006** | Générateur aléatoire non-cryptographique | CRITIQUE |

#### Exemples Python

```python
# ❌ CRITIQUE - IV statique/réutilisé
from Crypto.Cipher import AES
iv = b'0000000000000000'  # IV constant = dangereux
cipher = AES.new(key, AES.MODE_CBC, iv)

# ❌ CRITIQUE - Vérification SSL désactivée
import requests
requests.get('https://api.example.com', verify=False)

import ssl
context = ssl._create_unverified_context()

# ❌ CRITIQUE - Générateur non-cryptographique pour crypto
import random
key = random.getrandbits(128)  # random n'est pas cryptographiquement sûr
iv = bytes([random.randint(0, 255) for _ in range(16)])

# ❌ ÉLEVÉ - Salt manquant
import hashlib
hashed = hashlib.sha256(password.encode()).hexdigest()  # Pas de salt

# ❌ ÉLEVÉ - PBKDF2 avec trop peu d'itérations
from Crypto.Protocol.KDF import PBKDF2
key = PBKDF2(password, salt, dkLen=32, count=1000)  # < 100,000 itérations

# ❌ ÉLEVÉ - TLS 1.0 ou 1.1
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS 1.0 obsolète
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)  # TLS 1.1 obsolète

# ✅ CONFORME - IV aléatoire
import os
from Crypto.Cipher import AES
iv = os.urandom(16)  # IV cryptographiquement aléatoire
cipher = AES.new(key, AES.MODE_CBC, iv)

# ✅ CONFORME - SSL avec vérification
import requests
requests.get('https://api.example.com', verify=True)  # ou simplement omettre

# ✅ CONFORME - Générateur cryptographique
import secrets
key = secrets.token_bytes(32)
iv = secrets.token_bytes(16)

# ✅ CONFORME - Hash avec salt
import hashlib
import os
salt = os.urandom(32)
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# ✅ CONFORME - PBKDF2 avec itérations suffisantes
from Crypto.Protocol.KDF import PBKDF2
key = PBKDF2(password, salt, dkLen=32, count=100000)  # >= 100,000

# ✅ CONFORME - TLS 1.2 minimum
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.minimum_version = ssl.TLSVersion.TLSv1_2
```

---

### 1.4 Détection de l'absence de protection

#### Objectif
Identifier les cas où des mécanismes de sécurité essentiels sont absents.

#### Règles de détection

| ID Règle | Description | Sévérité |
|----------|-------------|----------|
| **PROT-001** | Transmission de données sensibles sans chiffrement | CRITIQUE |
| **PROT-002** | Stockage de mots de passe sans hachage | CRITIQUE |
| **PROT-003** | Absence de validation des entrées avant crypto | ÉLEVÉ |
| **PROT-004** | Pas de gestion des exceptions crypto | MOYEN |
| **PROT-005** | Logs contenant des données sensibles | ÉLEVÉ |

#### Exemples Python

```python
# ❌ CRITIQUE - Transmission en clair
import requests
# Envoi de données sensibles en HTTP (pas HTTPS)
requests.post('http://api.example.com/login', data={'password': password})

# ❌ CRITIQUE - Stockage de mot de passe en clair
user.password = password  # Stockage direct sans hachage

# ❌ ÉLEVÉ - Pas de validation avant déchiffrement
def decrypt_data(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)  # Pas de vérification de l'authenticité

# ❌ ÉLEVÉ - Logs avec secrets
import logging
logging.info(f"User logged in with password: {password}")
logging.debug(f"API Key: {api_key}")

# ❌ MOYEN - Pas de gestion d'erreur
plaintext = cipher.decrypt(ciphertext)
# Si le déchiffrement échoue, l'exception n'est pas gérée

# ✅ CONFORME - HTTPS obligatoire
import requests
requests.post('https://api.example.com/login', data={'password': password})

# ✅ CONFORME - Hachage de mot de passe
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
user.password_hash = hashed

# ✅ CONFORME - Chiffrement authentifié
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Déchiffrement avec vérification
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
except ValueError:
    # Tag invalide = données corrompues ou falsifiées
    raise AuthenticationError("Données corrompues")

# ✅ CONFORME - Logs sans secrets
import logging
logging.info(f"User {username} logged in")  # Pas de mot de passe
logging.debug("API call successful")  # Pas de clé
```

---

### 1.5 Tableau récapitulatif des règles générales

| Catégorie | ID Règle | Description | Sévérité |
|-----------|----------|-------------|----------|
| **Secrets** | SEC-001 | Clé cryptographique codée en dur | CRITIQUE |
| | SEC-002 | Mot de passe en clair | CRITIQUE |
| | SEC-003 | Token d'API en clair | CRITIQUE |
| | SEC-004 | Certificat/clé privée dans le code | CRITIQUE |
| | SEC-005 | Connection string avec credentials | ÉLEVÉ |
| **Algorithmes** | ALGO-001 | Utilisation de MD5 | CRITIQUE |
| | ALGO-002 | Utilisation de SHA-1 | CRITIQUE |
| | ALGO-003 | Utilisation de DES | CRITIQUE |
| | ALGO-004 | Utilisation de RC4 | CRITIQUE |
| | ALGO-005 | Mode ECB | ÉLEVÉ |
| | ALGO-006 | Triple DES faible | ÉLEVÉ |
| | ALGO-007 | Chiffrement sans authentification | MOYEN |
| **Configuration** | CONFIG-001 | IV/Nonce réutilisé | CRITIQUE |
| | CONFIG-002 | Salt manquant | ÉLEVÉ |
| | CONFIG-003 | PBKDF2 itérations < 100k | ÉLEVÉ |
| | CONFIG-004 | SSL vérification désactivée | CRITIQUE |
| | CONFIG-005 | TLS obsolète | ÉLEVÉ |
| | CONFIG-006 | Random non-cryptographique | CRITIQUE |
| **Protection** | PROT-001 | HTTP au lieu de HTTPS | CRITIQUE |
| | PROT-002 | Mot de passe non haché | CRITIQUE |
| | PROT-003 | Pas de validation avant crypto | ÉLEVÉ |
| | PROT-004 | Pas de gestion d'exceptions | MOYEN |
| | PROT-005 | Logs avec données sensibles | ÉLEVÉ |

---

## 2. Cryptographie Symétrique (Règles Techniques ANSSI)

### 2.1 Vérification des tailles de clés

#### Règles (obligatoires)

| Référence | Description | Période d'application |
|-----------|-------------|----------------------|
| **RègleCléSym-1** | Taille minimale de clé : **112 bits** | Jusqu'au 31/12/2025 |
| **RègleCléSym-2** | Taille minimale de clé : **128 bits** | À partir du 01/01/2026 |

#### Recommandations

| Référence | Description |
|-----------|-------------|
| **RecommandationCléSym** | Taille recommandée : **128 bits** (quelle que soit la période) |

**Implémentation SAST pour Python :**
- Détecter les instanciations d'algorithmes symétriques (AES, DES, 3DES)
- Extraire la taille de clé utilisée
- Vérifier la conformité selon la date d'utilisation prévue
- Niveau de sévérité : **CRITIQUE** si règle non respectée, **AVERTISSEMENT** si recommandation non suivie

**Exemples Python :**
```python
from Crypto.Cipher import DES, DES3, AES
import os

# ❌ Non conforme (clé de 56 bits)
key_des = os.urandom(8)  # 64 bits dont 8 de parité = 56 bits effectifs
cipher = DES.new(key_des, DES.MODE_CBC)

# ⚠️ Acceptable jusqu'en 2025, mais non recommandé (112 bits)
key_3des = os.urandom(16)  # Triple DES avec 2 clés = 112 bits
cipher = DES3.new(key_3des, DES.MODE_CBC)

# ✅ Conforme et recommandé (128 bits minimum)
key_aes128 = os.urandom(16)  # 128 bits
cipher = AES.new(key_aes128, AES.MODE_CBC)

# ✅ Conforme (192 bits)
key_aes192 = os.urandom(24)
cipher = AES.new(key_aes192, AES.MODE_CBC)

# ✅ Conforme (256 bits)
key_aes256 = os.urandom(32)
cipher = AES.new(key_aes256, AES.MODE_CBC)
```

### 2.2 Vérification des tailles de blocs

#### Règles (obligatoires)

| Référence | Description | Période d'application |
|-----------|-------------|----------------------|
| **RègleBlocSym-1** | Taille minimale de bloc : **64 bits** | Jusqu'au 31/12/2025 |
| **RègleBlocSym-2** | Taille minimale de bloc : **128 bits** | À partir du 01/01/2026 |

**Implémentation SAST pour Python :**
- Identifier l'algorithme de chiffrement par bloc utilisé
- Vérifier la taille de bloc (DES/3DES = 64 bits, AES = 128 bits)
- Alerter sur l'utilisation de blocs de 64 bits après 2026

**Exemples Python :**
```python
from Crypto.Cipher import DES, DES3, AES

# ❌ Non conforme à partir de 2026 (bloc de 64 bits)
cipher = DES3.new(key, DES.MODE_CBC)  # Bloc de 64 bits

# ✅ Conforme (bloc de 128 bits)
cipher = AES.new(key, AES.MODE_CBC)  # Bloc de 128 bits
```

### 2.3 Modes d'intégrité (MAC)

#### Mécanismes conformes
- **CBC-MAC "retail"** avec AES et deux clés distinctes
- **HMAC** avec SHA-2

#### Mécanismes non conformes
- CBC-MAC avec DES (même avec 112 bits de clé)
- CBC-MAC sans surchiffrement pour messages de taille variable

**Exemples Python :**
```python
from Crypto.Cipher import AES, DES
from Crypto.Hash import HMAC, SHA256
import hmac
import hashlib

# ❌ Non conforme - CBC-MAC avec DES
cipher = DES.new(key, DES.MODE_CBC)
mac = cipher.encrypt(padded_message)[-8:]  # Dernier bloc

# ⚠️ À éviter - CBC-MAC simple sans surchiffrement
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
mac = cipher.encrypt(padded_message)[-16:]

# ✅ Conforme - HMAC avec SHA-256 (bibliothèque standard)
mac = hmac.new(key, message, hashlib.sha256).digest()

# ✅ Conforme - HMAC avec SHA-256 (PyCryptodome)
h = HMAC.new(key, digestmod=SHA256)
h.update(message)
mac = h.digest()

# ✅ Conforme - HMAC avec SHA-512
mac = hmac.new(key, message, hashlib.sha512).digest()

# ✅ Meilleure approche - Chiffrement authentifié (GCM)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

---

## 3. Cryptographie Asymétrique (Règles Techniques ANSSI)

### 3.1 Problème de la factorisation (RSA)

#### Règles (obligatoires)

| Référence | Description | Période d'application |
|-----------|-------------|----------------------|
| **RègleFactorisation-1** | Module RSA ≥ **2048 bits** | Jusqu'au 31/12/2030 |
| **RègleFactorisation-2** | Module RSA ≥ **3072 bits** | À partir du 01/01/2031 |
| **RègleFactorisation-3** | Exposants secrets = taille du module | Toujours |
| **RègleFactorisation-4** | Exposants publics > **65536** (2^16) pour le chiffrement | Toujours |

#### Recommandations

| Référence | Description |
|-----------|-------------|
| **RecommandationFactorisation-1** | Module ≥ **3072 bits** même avant 2031 |
| **RecommandationFactorisation-2** | Exposants publics > **65536** pour toute application |
| **RecommandationFactorisation-3** | Nombres premiers p et q de même taille, choisis aléatoirement |

**Exemples Python :**
```python
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ❌ Non conforme (module trop petit)
key = RSA.generate(1024)  # 1024 bits insuffisant

# ❌ Non conforme - cryptography
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,  # Trop petit
    backend=default_backend()
)

# ⚠️ Conforme jusqu'en 2030, mais non recommandé
key = RSA.generate(2048)

# ✅ Conforme et recommandé
key = RSA.generate(3072)

# ✅ Conforme - cryptography
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
    backend=default_backend()
)

# ✅ Très fort (4096 bits)
key = RSA.generate(4096)

# ❌ Exposant public trop petit pour le chiffrement
key = RSA.generate(2048, e=3)  # e = 3 déconseillé

# ✅ Exposant public acceptable
key = RSA.generate(3072, e=65537)  # e = 65537 recommandé
```

---

### 3.2 Chiffrement asymétrique

#### Recommandations

| Référence | Description |
|-----------|-------------|
| **RecommandationChiffAsym-1** | Utiliser des mécanismes avec **preuve de sécurité** |

#### Mécanismes conformes
- **RSAES-OAEP** (PKCS#1 v2.1) avec respect des règles de factorisation

#### Mécanismes non conformes
- **RSAES (PKCS#1 v1.5)** en présence d'oracle de vérification de padding
  - Vulnérabilité : Attaque de Bleichenbacher (1998)
  - Permet de déchiffrer sans connaître la clé privée

**Exemples Python :**
```python
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ❌ Non conforme (PKCS#1 v1.5 - vulnérable à Bleichenbacher)
key = RSA.import_key(public_key)
cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message)

# ✅ Conforme (OAEP avec SHA-256)
key = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
ciphertext = cipher.encrypt(message)

# ✅ Conforme - cryptography avec OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Déchiffrement conforme
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

---

### 3.3 Signature asymétrique

#### Recommandations

| Référence | Description |
|-----------|-------------|
| **RecommandationSignAsym-1** | Utiliser des mécanismes avec **preuve de sécurité** |

#### Mécanismes conformes
- **RSA-SSA-PSS** (PKCS#1 v2.1) avec respect des règles de factorisation
- **ECDSA** (FIPS 186-4) avec courbes approuvées
- **ECKCDSA** avec courbes approuvées

#### Courbes elliptiques conformes
- **FRP256v1** (validée ANSSI, Journal Officiel n°241 du 16/10/2011)
- **P-256, P-384, P-521** (FIPS 186-4) - aussi appelées secp256r1, secp384r1, secp521r1
- **B-283, B-409, B-571** (FIPS 186-4)

#### Mécanismes non conformes
- **RSASSA (PKCS#1 v1.5)** avec :
  - Exposant public petit (e petit)
  - Mauvaise implantation des vérifications de padding
  - Vulnérabilité : Attaque de Bleichenbacher (2006) permettant la forge de signatures

**Exemples Python :**
```python
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec

# ❌ Non conforme (PKCS#1 v1.5)
key = RSA.import_key(private_key_pem)
h = SHA256.new(message)
signature = pkcs1_15.new(key).sign(h)

# ✅ Conforme (PSS recommandé)
key = RSA.import_key(private_key_pem)
h = SHA256.new(message)
signature = pss.new(key).sign(h)

# ✅ Conforme - cryptography avec PSS
from cryptography.hazmat.primitives.asymmetric import padding

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Vérification PSS
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature valide")
except Exception:
    print("Signature invalide")

# ✅ Conforme - ECDSA avec courbe P-256
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())  # P-256
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# ✅ Conforme - ECDSA avec P-384
private_key = ec.generate_private_key(ec.SECP384R1())
signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))

# ❌ Non conforme - Courbe non approuvée
private_key = ec.generate_private_key(ec.SECP256K1())  # secp256k1 (Bitcoin) non ANSSI

# ✅ Conforme - PyCryptodome ECDSA
key = ECC.generate(curve='P-256')
h = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)
```

---

## 4. Fonctions de hachage

#### Règles applicables
Les fonctions de hachage doivent avoir une empreinte suffisamment longue pour résister aux attaques par collision.

#### Mécanismes conformes
- **SHA-2** (SHA-224, SHA-256, SHA-384, SHA-512)
- **SHA-3** (Keccak) - en attente de validation ANSSI complète

#### Mécanismes non conformes
- **SHA-1** : vulnérable aux collisions (complexité estimée à 2^63)
  - Ne respecte ni RègleHash-1 ni RègleHash-2
  - Niveau de sécurité inférieur à 2^80
- **MD5** : définitivement cassé

**Exemples Python :**
```python
import hashlib
from Crypto.Hash import SHA256, SHA512, SHA1, MD5

# ❌ Non conforme (MD5 - complètement cassé)
hash_obj = hashlib.md5()
hash_obj = hashlib.md5(data)
hash_obj.update(data)

h = MD5.new()
h.update(data)

# ❌ Non conforme (SHA-1 - vulnérable aux collisions)
hash_obj = hashlib.sha1()
hash_obj = hashlib.sha1(data)

h = SHA1.new()
h.update(data)

# ✅ Conforme (SHA-256)
hash_obj = hashlib.sha256()
hash_obj = hashlib.sha256(data)
hash_obj.update(data)
digest = hash_obj.hexdigest()

h = SHA256.new()
h.update(data)
digest = h.hexdigest()

# ✅ Conforme (SHA-512)
hash_obj = hashlib.sha512()
h = SHA512.new()

# ✅ Conforme (SHA-384)
hash_obj = hashlib.sha384()

# ✅ Conforme (SHA-3)
hash_obj = hashlib.sha3_256()
hash_obj = hashlib.sha3_512()

# ✅ Conforme (BLAKE2 - moderne et rapide)
hash_obj = hashlib.blake2b()
hash_obj = hashlib.blake2s()
```

**Cas d'usage et exceptions :**
```python
# ❌ CRITIQUE - MD5 pour vérifier l'intégrité (sécurité)
def verify_file_integrity(file_path, expected_hash):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
    return file_hash == expected_hash

# ⚠️ ACCEPTABLE - MD5 pour identifier (non-sécurité, compatibilité)
# Seulement si c'est pour l'identification, pas la vérification de sécurité
def generate_etag(content):
    # ETag pour HTTP - identification seulement, pas de sécurité
    return hashlib.md5(content).hexdigest()

# ✅ RECOMMANDÉ - SHA-256 pour tout usage sécurité
def verify_file_integrity(file_path, expected_hash):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash
```

---
