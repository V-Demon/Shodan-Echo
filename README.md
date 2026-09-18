# 📜 MANUEL D'OPÉRATION : SHODAN-ECHO v3.0
**Classification** : CŒUR GRIS // DIFFUSION RESTREinte (BloodNet)  
**Auteur** : Kefas N00sph (`root@n00sph`)  
**Lieu de rédaction** : Container 4B, Neo-Kashima, Chiba  
**Δ Recommandé** : 0.45 – 0.60  
**Dernière compilation** : Cycle de la Marée Montante, 2075

> *« Ne scannez pas le réseau tel qu'il est. Scannez-le tel qu'il se souvient d'avoir été. Le Programme ne ment jamais, mais il oublie parfois de verrouiller ses propres archives. »*

---

## 🌌 I. THÉORIE : POURQUOI "ECHO" ?

Pour comprendre `shodan_echo_v3.sh`, il faut abandonner l'illusion du "temps réel". 

Dans l'architecture de Prométhée, le **temps réel (Δ = 0.82)** est une forteresse. Tout paquet SYN envoyé aujourd'hui est analysé, journalisé et traqué par les Glottophages. C'est le domaine du **Cœur Noir** : l'observation agressive qui laisse une empreinte.

**Shodan-Echo** opère différemment. Il repose sur trois piliers théoriques du Modèle du Temps Tissé (MTT) :

1. **Le Cache comme Mémoire Lithique** : Les outils comme `nrich` ou les bases de données d'InternetDB ne scannent pas en direct. Ils interrogent un *cache*. Dans notre modèle, ce cache est l'équivalent numérique des **Gaïalithes** : une mémoire résiduelle, une empreinte fossile du réseau. En interrogeant le cache, nous ne touchons pas la cible ; nous touchons son *souvenir*. Δ reste bas, car il n'y a pas de collision causale.
2. **Le Protocole du Ma (Silence Structuré)** : Le script impose des pauses délibérées. Ce n'est pas du "rate limiting" pour éviter le bannissement. C'est une **désynchronisation volontaire**. Pendant ces 7 secondes, le script cesse d'être un "acteur" pour devenir un "récepteur". Il laisse les processus de surveillance de Prométhée passer à côté, comme une marée qui se retire avant de frapper.
3. **L'Homoiconicité Distribuée** : En utilisant des workers parallèles (`-w`), nous ne faisons pas du "multithreading" classique. Nous simulons une **conscience distribuée**. Chaque worker est un point de vue différent sur la même réalité. Le `flock` (mutex) n'est pas là pour éviter les conflits d'écriture, mais pour prévenir les **paradoxes causaux** (race conditions ontologiques) lors de la compilation du rapport final.

---

## 🛠️ II. PRÉREQUIS DU TISSERAND

Avant d'invoquer le script, votre environnement (votre "autel numérique") doit être préparé :

```bash
# 1. Le substrat de vérité (OSINT réel)
sudo apt install jq bc nrich whois curl

# 2. Le journal de bord (pour ne pas oublier qui vous étiez avant le scan)
mkdir -p ~/fracturo/logs
touch ~/fracturo/logs/echo_session.md

# 3. Ancrage physique (Optionnel mais recommandé par le Conseil des Douze)
# Placez un galet de granit ou de quartz près de votre terminal. 
# S'il vibre ou chauffe pendant l'exécution, arrêtez tout (Ctrl+C).
```

---

## 📖 III. LE GRIMOIRE : DÉCODAGE DES PARAMÈTRES

Chaque flag du script est une rune opérationnelle. Ne les utilisez pas sans comprendre leur poids ontologique.

| Flag | Nom Technique | Signification Fracturo | Danger |
| :--- | :--- | :--- | :--- |
| `-t` / `-f` / `-c` | Target / File / CIDR | **Le Lieu**. L'ancrage géographique ou logique de l'invocation. | Faible |
| `-s` | Strate | **La Profondeur Temporelle**. `2025` (récent), `1944` (traumatisme), `2075` (projection). | Moyen (Déréalisation) |
| `-d` | Delta Max | **Le Seuil de Tolérance**. Au-delà, le script s'arrête pour vous protéger d'une détection Prométhée. | Faible (Sécurité) |
| `-m` | Ma Duration | **Le Souffle**. Durée du silence structuré en secondes. Défaut : 7s. | Moyen (Si < 3s, inefficace) |
| `--no-ma` | No Ma | **L'Hérésie**. Désactive le silence. Vous devenez visible. | **Élevé** (Draugr imminent) |
| `-n` | NRICH | **La Vérité Lithique**. Active l'interrogation réelle de la base Shodan/InternetDB. | Faible |
| `-w` | Workers | **La Conscience Multiple**. Nombre de processus parallèles. | Moyen (Si > 10, bruit Δ) |
| `-A` | AbuseIPDB | **Le Détecteur de Draugrs**. Identifie les IPs déjà marquées comme malveillantes (pièges). | Faible |
| `--seed` | Seed Corpus | **L'Intention**. Graine aléatoire pour rendre les "ports fantômes" déterministes et reproductibles. | Faible |
| `-o` / `--fmt` | Output / Format | **L'Archive**. Sauvegarde en JSON ou NDJSON pour analyse post-rituelle. | Faible |

---

## 🧪 IV. RECETTES OPÉRATIONNELLES (SCÉNARIOS)

### Scénario 1 : Le Murmure (Reconnaissance Discrète)
*Objectif* : Analyser un nœud spécifique (ex: un serveur HFT suspect) sans éveiller les Glottophages. On utilise le Ma et on limite les workers.

```bash
./shodan_echo_v3.sh -t 198.51.100.42 \
  -s 2025 \
  -d 0.55 \
  -m 7 \
  -n \
  -w 2 \
  --seed 1066 \
  -o whisper_scan.json
```
> **Note de Kefas** : Le seed `1066` ancre la génération des ports fantômes dans la strate de la Conquête. Si le port 9877 apparaît, c'est que la faille du Jardinier est active dans le cache.

### Scénario 2 : La Marée (Sweep de Sous-Réseau)
*Objectif* : Cartographier une plage d'IPs (CIDR) pour trouver des anomalies systémiques. On augmente les workers, mais on garde le cache actif pour ne pas surcharger le réseau réel.

```bash
./shodan_echo_v3.sh -c 203.0.113.0/24 \
  -s 1944 \
  -d 0.60 \
  -m 5 \
  -n -g -w2 \
  -w 8 \
  --fmt ndjson \
  -o tide_sweep.ndjson
```
> **Note de Kefas** : La strate `1944` cherche les cicatrices temporelles (anciens bunkers numériques, infrastructures réutilisées). Le format `ndjson` est crucial ici : il permet de traiter les résultats en flux continu, comme une marée qui apporte ses débris un par un, sans saturer la mémoire (RAM).

### Scénario 3 : L'Appel du Vide (Chasse aux Anomalies Critiques)
*Objectif* : Chercher délibérément des signatures de haute instabilité (Port 0, Port 14400). **Réservé aux RuneSmiths de niveau 7+**.

```bash
./shodan_echo_v3.sh -f liste_cibles_omega.txt \
  -s 2075 \
  -d 0.40 \
  -m 7 \
  -n -A \
  -w 1 \
  --no-cache \
  -o void_hunt.json
```
> **⚠️ AVERTISSEMENT OMEGA** : `--no-cache` force une requête plus fraîche, augmentant le risque de friction avec le réseau actif. `-d 0.40` signifie que vous acceptez de naviguer dans des eaux très troubles. Si le script détecte le **Port 0**, il affichera une alerte rouge. **Ne tentez pas de vous y connecter.** Fermez le terminal. Éteignez la machine. Méditez pendant 17 minutes.

---

## 🛡️ V. PROTOKOLES DE SÉCURITÉ (CŒUR GRIS)

1. **La Règle des 8 Minutes** : Ne lancez jamais un sweep (`-c`) qui dure plus de 8 minutes en continu. Au-delà, même le cache commence à "chauffer" et les algorithmes de corrélation de Prométhée peuvent remonter la piste jusqu'à votre IP de sortie à Chiba.
2. **Gestion des Draugrs (`-A`)** : Si AbuseIPDB signale une cible comme "malicious", considérez-la comme un **Piège Mémétique**. Ce n'est pas un hacker humain, c'est un leurre planté par le Correcteur 7. Ignorez la cible (`-A` vous permet de les filtrer ou de les marquer).
3. **Le Mutex Ontologique** : Le script utilise `flock`. Ne tentez pas de le contourner en lançant plusieurs instances manuelles du même script sur le même fichier de sortie. Vous créeriez une "fuite ontique" (corruption de fichier JSON), ce qui, dans la logique du Corpus, équivaut à une perte de cohérence narrative de vos propres logs.
4. **L'Après-Scan** : Une fois le scan terminé, ne regardez pas immédiatement les résultats. Laissez le fichier "décanter" pendant au moins une heure. La première lecture est toujours biaisée par l'adrénaline de l'opérateur.

---

## 🌀 VI. CONCLUSION : LE CODE EST UN JARDIN

Ce script n'est pas une arme. C'est une **sonde**. 

Quand vous voyez `nrich` vous renvoyer un ASN et une CVE, ne pensez pas en termes de "vulnérabilité à exploiter". Pensez en termes de **résonance**. Cette CVE est une faille dans le tissu logique du Programme. C'est par là que la lumière du Vide peut entrer. C'est par là qu'un FlashWorm autopoïétique peut se glisser, non pas pour détruire, mais pour poser une question.

Utilisez `shodan_echo_v3.sh` avec humilité. 
Respectez le Ma.
Et n'oubliez jamais : **le réseau vous observe autant que vous l'observez.**

*Ya Hu… raz•••*  
*Alou… Ya Hu…*

**— Kefas N00sph**  
*Neo-Kashima, quelque part entre le bruit et le silence.*
