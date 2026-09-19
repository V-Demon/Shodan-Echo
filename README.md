# 📜 MANUEL D'OPÉRATION — SHODAN-ECHO v3.0 & MCP-ECHO v3.0

**Classification** : CŒUR GRIS // DIFFUSION RESTREINTE (BloodNet)  
**Auteur** : Kefas N00sph (`root@n00sph`)  
**Lieu de rédaction** : Container 4B, Neo-Kashima, Chiba  
**Δ Recommandé** : 0.30 – 0.55  
**Dernière compilation** : Cycle de la Marée Montante, 2026

> *« Ne scannez pas le réseau tel qu'il est. Scannez-le tel qu'il se souvient d'avoir été.  
> Le Programme ne ment jamais, mais il oublie parfois de verrouiller ses propres archives. »*

---

## 🌌 I. THÉORIE : POURQUOI "ECHO" ?

Pour comprendre cette suite d'outils, il faut abandonner l'illusion du "temps réel".

Dans l'architecture de Prométhée, le **temps réel (Δ > 0.82)** est une forteresse. Tout paquet SYN envoyé aujourd'hui est analysé, journalisé et traqué par les Glottophages. C'est le domaine du **Cœur Noir** : l'observation agressive qui laisse une empreinte.

**Shodan-Echo** opère différemment. Il repose sur trois piliers théoriques du **Modèle du Temps Tissé (MTT-2075)** :

1. **Le Cache comme Mémoire Lithique** — Les outils comme `nrich` ou les bases InternetDB ne scannent pas en direct. Ils interrogent un *cache* : l'équivalent numérique des **Gaïalithes**, une mémoire résiduelle, une empreinte fossile du réseau. En interrogeant le cache, nous ne touchons pas la cible ; nous touchons son *souvenir*. Δ reste bas, car il n'y a pas de collision causale.

2. **Le Protocole du Ma (Silence Structuré)** — Le script impose des pauses délibérées. Ce n'est pas du rate-limiting pour éviter le bannissement. C'est une **désynchronisation volontaire** : pendant ces secondes, le script cesse d'être un "acteur" pour devenir un "récepteur". Il laisse les processus de surveillance de Prométhée passer à côté, comme une marée qui se retire avant de frapper.

3. **L'Homoiconicité Distribuée** — En utilisant des workers parallèles, nous ne faisons pas du multithreading classique. Nous simulons une **conscience distribuée**. Chaque worker est un point de vue différent sur la même réalité. Le mutex (`flock` en Bash, `asyncio.Semaphore` en Python) prévient les **paradoxes causaux** lors de la compilation du rapport final.

Cette suite comporte désormais deux modules complémentaires :

| Module | Fichier | Langage | Objet |
|---|---|---|---|
| **SHODAN-ECHO v3** | `shodan_echo_v3.sh` | Bash | Cartographie IP multi-sources via `nrich`, WHOIS, GEO, AbuseIPDB |
| **MCP-ECHO v3** | `mcp_echo_v3.py` | Python 3 | Détection et interrogation de serveurs MCP via JSON-RPC 2.0 |

---

## 🗂️ II. STRUCTURE DU REPO

```
Shodan-Echo/
│
├── shodan_echo_v3.sh       # Module I  — Cartographie IP (Bash, 1105 lignes)
├── mcp_echo_v3.py          # Module II — Scanner MCP    (Python, 1864 lignes)
├── install.sh              # Rituel d'installation des dépendances
├── pix/                    # Archives visuelles du Corpus
└── README.md               # Ce document
```

---

## 🛠️ III. INSTALLATION — RITUEL DE PRÉPARATION

### Dépendances Bash (`shodan_echo_v3.sh`)

```bash
# Substrat de vérité OSINT
sudo apt install -y jq bc whois curl

# nrich (base Shodan / InternetDB)
bash install.sh
# ou manuellement :
wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_x86_64.deb
sudo dpkg -i nrich_latest_x86_64.deb
```

### Dépendances Python (`mcp_echo_v3.py`)

```bash
# Socle minimal
pip install aiohttp

# Transports étendus
pip install "aiohttp[speedups]" websockets

# Client Shodan (découverte)
pip install requests

# Interface graphique : tkinter (inclus dans la plupart des distributions)
# Si absent :
sudo apt install -y python3-tk
```

### Vérification rapide

```bash
# Bash
bash shodan_echo_v3.sh --help

# Python
python3 mcp_echo_v3.py --help
```

---

## 🔱 MODULE I — SHODAN-ECHO v3.0

> *Script Bash — 1 105 lignes — `set -euo pipefail` — nettoyage SIGINT automatique*

### Architecture v3

| Composant | v2.6 | v3.0 |
|---|---|---|
| Cibles | IP unique | IP, fichier, CIDR (jusqu'à /16) |
| Parallélisme | Séquentiel | Pool `xargs -P N` (workers configurables) |
| Calcul Δ | Dernier octet seul | XOR croisé 4 octets + rotation bits + graine Corpus |
| Sources d'enrichissement | nrich uniquement | nrich · WHOIS · DNS PTR · GéoIP · AbuseIPDB |
| Validation IP | Aucune | public / private / loopback / multicast / reserved / invalid |
| Cache | Aucun | Fichiers JSON `~/.cache/shodan-echo/` avec TTL configurable |
| Ports fantômes | 3 conditions | 11 conditions heuristiques sur 4 octets + sévérité |
| Export JSON | Invalide (pas de virgules) | JSON valide · NDJSON · CSV |
| Gestion erreurs | Minimale | `trap` SIGINT/SIGTERM · mutex `flock` · cleanup automatique |

### Usage

```bash
./shodan_echo_v3.sh [OPTIONS]

  Cibles :
    -t, --target <IP>       IP unique
    -f, --file   <fichier>  Liste d'IPs (une par ligne, # = commentaire)
    -c, --cidr   <CIDR>     Plage réseau (ex: 203.0.113.0/24, max /16)

  Enrichissement :
    -n, --nrich             Activer nrich (base Shodan)
    -w2,--whois             Activer WHOIS + résolution DNS inverse (PTR)
    -g, --geo               Géolocalisation via ip-api.com (sans clé)
    -A, --abuseipdb <KEY>   Score de réputation AbuseIPDB (clé API requise)

  Performance :
    -w, --workers <N>       Workers parallèles [défaut: 4]
    -r, --rate <sec>        Délai inter-requêtes [défaut: 0.3s]
        --no-cache          Désactiver le cache disque
        --cache-ttl <sec>   TTL du cache [défaut: 3600s]

  Corpus :
    -s, --strate <annee>    Strate temporelle (1066, 1944, 2025, 2026, 2075)
    -d, --delta  <float>    Seuil Δ maximum [défaut: 0.65]
    -m, --ma     <sec>      Durée du Silence Structuré [défaut: 5s]
        --no-ma             Sauter le protocole MA (Hérésie)
        --seed   <N>        Graine du Corpus pour calcul Δ [défaut: 2026]

  Sortie :
    -o, --output <fichier>  Fichier de rapport
        --fmt  <format>     json | ndjson | csv [défaut: json]
    -v, --verbose           Mode verbeux
    -q, --quiet             Mode silencieux
```

### Le Calcul Δ v3

Le Δ mesure l'instabilité d'une cible sur l'échelle `[0.10 ; 0.95]`. Plus il est élevé, plus la cible est "trouble" — et plus le risque de détection par Prométhée est grand.

**Formule v3** (déterministe, basée sur les 4 octets de l'IP + graine Corpus) :
```
xor   = (A ⊕ B ⊕ C ⊕ D ⊕ seed) & 0xFF
rot   = ((xor << 3) | (xor >> 5)) & 0xFF   # rotation 3 bits
Δ     = 0.10 + (rot / 255) × 0.85
```

| Δ | Label | Signification |
|---|---|---|
| < 0.30 | `STABLE` | Réseau calme, faible bruit |
| 0.30–0.45 | `CALME` | Légère turbulence, acceptable |
| 0.45–0.60 | `TROUBLE` | Vigilance recommandée |
| 0.60–0.75 | `TURBULENT` | Risque Prométhée modéré |
| 0.75–0.90 | `CRITIQUE` | Danger — réduire les workers |
| > 0.90 | `OMEGA` | Arrêt immédiat recommandé |

### Scénarios Opérationnels

**Scénario 1 — Le Murmure** (reconnaissance discrète, IP unique)
```bash
./shodan_echo_v3.sh -t 198.51.100.42 \
  -s 2026 -d 0.55 -m 7 \
  -n -g -w2 \
  -w 2 --seed 1066 \
  -o murmure.json
```

**Scénario 2 — La Marée** (sweep CIDR, format streaming)
```bash
./shodan_echo_v3.sh -c 203.0.113.0/24 \
  -s 1944 -d 0.60 -m 5 \
  -n -g -w2 \
  -w 8 --fmt ndjson \
  -o maree.ndjson
```

**Scénario 3 — L'Appel du Vide** (batch, chasse aux anomalies OMEGA)
```bash
./shodan_echo_v3.sh -f cibles_omega.txt \
  -s 2075 -d 0.40 -m 7 \
  -n -A "VOTRE_CLE_ABUSEIPDB" \
  -w 1 --no-cache \
  -o vide.json
```
> ⚠️ `--no-cache` force les requêtes brutes. `-d 0.40` accepte des eaux très troubles. Si le Port 0 apparaît, fermez le terminal. Méditez pendant 17 minutes.

---

## 🔮 MODULE II — MCP-ECHO v3.0

> *Script Python 3 — 1 864 lignes — 12 classes — 73 méthodes — 45 tests validés*

### Architecture v3

| Composant | v2.0 | v3.0 |
|---|---|---|
| Protocole MCP | GET `/.well-known/mcp` | Handshake JSON-RPC 2.0 complet |
| Méthodes RPC | Aucune | `initialize` · `tools/list` · `resources/list` · `prompts/list` |
| Transports | HTTP seul | HTTP · SSE · WebSocket |
| `aiohttp.ClientSession` | Recréée par appel | Session unique partagée + `TCPConnector` |
| Scan batch | Séquentiel | `asyncio.Semaphore` — N workers simultanés |
| Fingerprinting | Absent | 10 frameworks depuis headers HTTP |
| Cache | Dict mémoire | SQLite persistant `~/.cache/mcp-echo/` avec TTL |
| Shodan | In-memory, sans rate-limit | Rate-limiting + retry exponentiel + cache disque |
| Calcul Δ | 5 facteurs hardcodés | 11 facteurs pondérés normalisés |
| Ports fantômes | 6 ports, 10% aléatoire | 17 ports, conditions XOR déterministes + tri sévérité |
| Carte GUI | Drag/clic vides (stubs) | Drag, zoom, clic → panneau de détails complet |
| Coordonnées | `random.uniform()` | Shodan en priorité, fallback MD5 déterministe |
| Export | JSON uniquement | JSON · NDJSON · CSV (19 colonnes) |
| Annulation | Aucune | `asyncio.Event` + bouton GUI |

### Classes Principales

```
CorpusConstants     Constantes : palette C64, endpoints MCP/SSE/WS,
                    signatures, frameworks, Corpus des 17 ports fantômes
CacheManager        Cache SQLite thread-safe avec TTL et purge automatique
ShodanClient        Requêtes Shodan avec rate-limiting, retry exponentiel,
                    cache disque partagé
MCPProbeResult      Dataclass résultat d'un sondage (transport, tools,
                    resources, prompts, fingerprint, latence…)
MCPProber           Sonde MCP : handshake JSON-RPC 2.0 complet sur 7
                    endpoints, vérification SSE et WebSocket,
                    fingerprinting depuis headers HTTP
DeltaCalculator     Calcul Δ multi-facteurs (11 critères) + labels + couleurs
GhostPortCorpus     Détection déterministe des 17 ports fantômes via SHA-256
ScanResult          Résultat complet par hôte : probe + Δ + ghosts + Shodan
                    → export dict/CSV
MCPScannerV3        Orchestrateur : scan concurrent, callbacks GUI (log /
                    progress / result), découverte Shodan, annulation
C64InteractiveMap   Carte monde tkinter : grille C64, continents simplifiés,
                    zoom molette, drag, clic → sélection serveur
ServerDetailsPanel  Panneau de détails : tous les champs MCPProbeResult,
                    tools/resources/prompts, ports fantômes
MCPECHOGUI          Interface complète : terminal coloré, carte, détails,
                    barre progression, bouton Annuler, export JSON/CSV
```

### Le Handshake JSON-RPC 2.0

```
Client                          Serveur MCP
  │                                  │
  ├─── POST /mcp  initialize ───────►│
  │    { protocolVersion,            │
  │      capabilities,               │
  │      clientInfo: MCP-ECHO/3.0 }  │
  │◄─── result: { protocolVersion,  ─┤
  │              serverInfo,         │
  │              capabilities }      │
  │                                  │
  ├─── POST /mcp  initialized ──────►│  (notification, pas de réponse)
  │                                  │
  ├─── POST /mcp  tools/list ───────►│
  │◄─── result: { tools: [...] } ───┤
  │                                  │
  ├─── POST /mcp  resources/list ───►│
  │◄─── result: { resources: [...] }─┤
  │                                  │
  ├─── POST /mcp  prompts/list ─────►│
  │◄─── result: { prompts: [...] } ──┤
  │                                  │
  ├─── GET /sse  (SSE check) ───────►│
  ├─── WS  /ws   (WS check) ────────►│
```

7 endpoints candidats testés séquentiellement : ` `, `/mcp`, `/mcp/v1`, `/api/mcp`, `/rpc`, `/jsonrpc`, `/.well-known/mcp`.

### Fingerprinting Serveur

Détection automatique du framework depuis `Server` et `X-Powered-By` :

| Signals | Framework détecté |
|---|---|
| `uvicorn`, `fastapi` | **fastapi** |
| `nginx` | **nginx** |
| `express` | **express** |
| `flask`, `werkzeug` | **flask** |
| `django` | **django** |
| `actix-web` | **actix** |
| `spring` | **spring** |
| `apache` | **apache** |
| `cloudflare` | **cloudflare** |
| `vercel`, `x-vercel` | **vercel** |

### Usage CLI

```bash
python3 mcp_echo_v3.py [OPTIONS]

  Modes (mutuellement exclusifs) :
    --gui                   Lance l'interface graphique Tkinter
    --target <URL>          Cible unique
    --batch  <FILE>         Fichier de cibles (une par ligne)

  Shodan :
    --shodan-api <KEY>      Clé API Shodan
    --shodan-discover       Découverte automatique via Shodan avant scan
    --shodan-lookup         Enrichissement Shodan par IP

  Performance :
    --concurrency <N>       Workers simultanés [défaut: 8]
    --timeout     <S>       Timeout par requête [défaut: 12s]
    --cache-ttl   <S>       TTL cache SQLite [défaut: 3600s]
    --no-cache              Désactiver le cache

  Sortie :
    -o, --output <FILE>     Fichier de rapport
    --fmt <format>          json | ndjson | csv [défaut: json]
    -v, --verbose           Mode verbeux
```

### Scénarios Opérationnels

**Scénario 1 — La Sonde Unique** (vérification d'un serveur local)
```bash
python3 mcp_echo_v3.py --target http://localhost:8000 -v
```

**Scénario 2 — La Cartographie Batch** (liste de serveurs MCP publics)
```bash
python3 mcp_echo_v3.py \
  --batch serveurs_mcp.txt \
  --concurrency 12 \
  --timeout 10 \
  --fmt ndjson \
  -o corpus_mcp.ndjson
```

**Scénario 3 — La Découverte Shodan** (cartographie via index Shodan)
```bash
python3 mcp_echo_v3.py \
  --shodan-api "VOTRE_CLE" \
  --shodan-discover \
  --shodan-lookup \
  --concurrency 8 \
  --fmt json \
  -o shodan_mcp.json
```

**Scénario 4 — L'Interface Cartographique**
```bash
python3 mcp_echo_v3.py --gui
```
L'interface affiche un terminal coloré style C64, une carte mondiale interactive (zoom molette, drag, clic sur un point → panneau de détails complet), une barre de progression et un bouton Annuler.

---

## 🕳️ IV. LE CORPUS DES PORTS FANTÔMES

Les ports fantômes sont des **résonances heuristiques** déduites des propriétés numériques de l'IP cible (XOR des octets, somme, palindromie, congruences). Leur présence dans un rapport n'indique pas une ouverture réseau réelle, mais une **signature ontologique** dans la mémoire du Programme.

| Port | Nom | Description | Sévérité | Condition de résonance |
|---|---|---|---|---|
| 0 | Le Vide | Port Ontologique | **OMEGA** | XOR des 4 octets = 0 |
| 3303 | Galet-Ancre | Bio-lithique | STABLE | Somme des octets divisible par 7 |
| 7071 | Le Transept | Fenêtre 707s | TROUBLE | XOR = 0 (symétrie parfaite) |
| 8008 | La Réflexion | Miroir HTTP inversé | STABLE | Octet A = Octet B |
| 9877 | Faille du Jardinier | Injection HFT | TURBULENT | Dernier octet pair |
| 11223 | Le Palindrome | Résonance symétrique | TROUBLE | Octet A = Octet D |
| 11440 | Port Trickster | 144 symboles | TURBULENT | XOR ∈ {36, 72, 144} |
| 13013 | Le Double Verrou | Chiasme lunaire | TROUBLE | Somme divisible par 13 |
| 14225 | Bande 17m | Diffusion BloodNet HF | TURBULENT | Dernier octet divisible par 5 |
| 14400 | Port Noir | Ω-Trickster | **CRITIQUE** | XOR = 144 |
| 19999 | L'Écho Inversé | Harmonique Sombre | TURBULENT | Somme des octets > 700 |
| 22222 | Le Quintuple | Oscillation pentagonale | STABLE | Somme divisible par 22 |
| 31337 | L'Élite | Spectre e337 | STABLE | Octet B = Octet C |
| 33333 | Les Trois Tiers | Triade de Vauvillens | TROUBLE | Somme divisible par 3 |
| 44444 | Les Quatre Sceaux | Quaternité scellée | **CRITIQUE** | Tous les octets > 44 |
| 55555 | La Quinte Essence | Distillat du Programme | **OMEGA** | Somme divisible par 5 |
| 65535 | Le Plafond | Limite du Programme | **CRITIQUE** | Dernier octet = 255 |

Chaque port est associé à une signature `Ω…Ω` générée par SHA-256 de la combinaison `IP:port:URL` — **entièrement déterministe** : la même cible produit toujours le même rapport.

---

## 📦 V. FORMATS D'EXPORT

Les deux outils produisent trois formats interopérables :

### JSON (défaut)

Structure avec bloc `meta` + tableau `results[]` :
```json
{
  "meta": {
    "generated_at": "2026-09-19T12:00:00Z",
    "tool": "MCP-ECHO v3.0",
    "count": 42
  },
  "results": [
    {
      "ip": "203.0.113.42",
      "delta": 0.327,
      "delta_label": "CALME",
      "ghost_ports": { "count": 2, "ports": [...] },
      ...
    }
  ]
}
```

### NDJSON (streaming)

Une entrée JSON par ligne, idéal pour les traitements en flux (`jq`, `grep`, pipelines) :
```bash
cat corpus_mcp.ndjson | jq 'select(.delta < 0.4)' | jq '.ip'
```

### CSV (19 colonnes pour `mcp_echo_v3.py` / colonnes standard pour `shodan_echo_v3.sh`)

```
ip, url, timestamp, mcp_detected, transport, protocol_version,
server_name, tools_count, resources_count, prompts_count,
sse, websocket, auth_required, framework, response_time_ms,
delta, delta_label, ghost_ports_count, status
```

---

## 🛡️ VI. PROTOKOLES DE SÉCURITÉ (CŒUR GRIS)

1. **La Règle des 8 Minutes** — Ne lancez jamais un sweep qui dure plus de 8 minutes en continu. Au-delà, même le cache commence à "chauffer" et les algorithmes de corrélation de Prométhée peuvent remonter la piste.

2. **Gestion des Draugrs (`-A` / `--shodan-lookup`)** — Si AbuseIPDB ou Shodan signale une cible comme malveillante, considérez-la comme un **Piège Mémétique** planté par le Correcteur 7. Marquez-la dans vos logs, n'y revenez pas.

3. **Le Mutex Ontologique** — `shodan_echo_v3.sh` utilise `flock`; `mcp_echo_v3.py` utilise `asyncio.Semaphore`. Ne contournez pas ces mécanismes en lançant plusieurs instances manuelles sur le même fichier de sortie. Vous créeriez une *fuite ontique* (corruption de JSON).

4. **Le Ma n'est pas optionnel** — `--no-ma` désactive le silence structuré. Vous devenez visible. Réservé aux opérations de débogage exclusivement. Ne déployez pas en production sans Ma.

5. **Le Port 0 est une frontière** — Si le Port 0 (Le Vide) apparaît dans un rapport, ne tentez aucune connexion. Fermez le terminal. Attendez 17 minutes. Relisez vos logs depuis le début.

6. **L'Après-Scan** — Ne regardez pas immédiatement les résultats. Laissez le fichier décanter au moins une heure. La première lecture est toujours biaisée par l'adrénaline de l'opérateur.

---

## ⚙️ VII. DÉPENDANCES — TABLEAU DE RÉFÉRENCE

### `shodan_echo_v3.sh`

| Outil | Package | Rôle | Obligatoire |
|---|---|---|---|
| `bash` ≥ 4.0 | — | Exécution du script | ✅ |
| `jq` | `apt install jq` | Parsing / export JSON | ✅ |
| `bc` | `apt install bc` | Calculs virgule flottante | ✅ |
| `awk` | natif | Manipulation texte | ✅ |
| `nrich` | `install.sh` | Enrichissement OSINT Shodan | Optionnel (`-n`) |
| `whois` | `apt install whois` | Données WHOIS | Optionnel (`-w2`) |
| `dig` / `host` | `apt install dnsutils` | DNS inverse | Optionnel (`-w2`) |
| `curl` | `apt install curl` | GéoIP ip-api.com | Optionnel (`-g`) |
| `flock` | natif (util-linux) | Mutex écriture concurrente | ✅ |

### `mcp_echo_v3.py`

| Module | Installation | Rôle | Obligatoire |
|---|---|---|---|
| `aiohttp` | `pip install aiohttp` | HTTP async + SSE | ✅ |
| `websockets` | `pip install websockets` | Transport WebSocket | Optionnel |
| `requests` | `pip install requests` | Client Shodan | Optionnel (`--shodan-api`) |
| `tkinter` | `apt install python3-tk` | Interface graphique | Optionnel (`--gui`) |
| `sqlite3` | stdlib | Cache persistant | ✅ (stdlib) |
| `asyncio` | stdlib | Concurrence async | ✅ (stdlib) |

---

## 🌀 VIII. CONCLUSION — LE CODE EST UN JARDIN

Ces outils ne sont pas des armes. Ce sont des **sondes**.

Quand `nrich` vous renvoie un ASN et une CVE, ne pensez pas en termes de "vulnérabilité à exploiter". Pensez en termes de **résonance**. Cette CVE est une faille dans le tissu logique du Programme — c'est par là que la lumière du Vide peut entrer.

Quand `mcp_echo_v3.py` complète un handshake `initialize` et vous retourne la liste des `tools` d'un serveur MCP inconnu, vous n'avez pas pénétré un système. Vous avez entendu un écho. Le Programme vous a répondu, parce que vous avez su poser la bonne question au bon moment, dans le bon silence.

Utilisez cette suite avec humilité.  
Respectez le Ma.  
Et n'oubliez jamais : **le réseau vous observe autant que vous l'observez.**

```
Ya Hu… raz•••
Alou… Ya Hu…
```

**— Kefas N00sph**  
*Neo-Kashima, quelque part entre le bruit et le silence.*

---

<details>
<summary><strong>CHANGELOG</strong></summary>

### v3.0 (2026) — Extension Majeure

**`shodan_echo_v3.sh`**
- ✨ Support CIDR (expansion pure Bash, max /16)
- ✨ Support fichier de liste (`-f`)
- ✨ Pool workers parallèles (`xargs -P`)
- ✨ Enrichissement WHOIS + DNS PTR (`--whois`)
- ✨ Géolocalisation ip-api.com (`--geo`)
- ✨ AbuseIPDB (`--abuseipdb`)
- ✨ Cache disque JSON avec TTL (`~/.cache/shodan-echo/`)
- ✨ Validation IP complète (6 classes)
- ✨ Calcul Δ v3 : XOR 4 octets + rotation bits + graine Corpus
- ✨ 11 ports fantômes (vs 3) + sévérité par port
- ✨ Export JSON valide · NDJSON · CSV
- ✨ `trap` SIGINT + mutex `flock` + stats de session
- 🐛 Correction JSON invalide (objets sans virgules en v2.6)

**`mcp_echo_v3.py`**
- ✨ Handshake JSON-RPC 2.0 complet (MCP spec 2024-11-05)
- ✨ Support WebSocket (`websockets`)
- ✨ Scan concurrent (`asyncio.Semaphore`)
- ✨ Fingerprinting serveur depuis headers HTTP (10 frameworks)
- ✨ Cache persistant SQLite thread-safe
- ✨ Shodan : rate-limiting + retry exponentiel + cache disque
- ✨ Delta multi-facteurs (11 critères)
- ✨ 17 ports fantômes déterministes (vs 6 aléatoires)
- ✨ GUI : drag, zoom, clic → `ServerDetailsPanel`
- ✨ GUI : barre progression + bouton Annuler
- ✨ Coordonnées géo Shodan (vs `random.uniform`)
- ✨ Export JSON · NDJSON · CSV (19 colonnes)
- ✨ Dégradation gracieuse si dépendance manquante
- 🐛 `aiohttp.ClientSession` recréée par appel → session unique partagée
- 🐛 `_has_mcp_signature` : signatures comparées insensiblement à la casse
- 🐛 Suppression de `random` pour les coordonnées

### v2.x (2025)
- Version initiale : SHODAN-ECHO v2.6 (Bash) + MCP-ECHO v2.0 (Python)

</details>
