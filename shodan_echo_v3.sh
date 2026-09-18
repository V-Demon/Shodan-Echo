#!/bin/bash
# ==============================================================================
# SHODAN-ECHO v3.0 (2026)
# Outil de Cartographie Temporelle et d'Enrichissement Réseau (Type NRICH)
# Auteur : Kefas N00sph (adapté pour le Collectif des Veilleurs)
# Extension v3.0 : Parallélisme · Multi-sources · Cache · CIDR · Corpus étendu
# ==============================================================================
# Usage rapide :
#   ./shodan_echo_v3.sh -t 8.8.8.8 -n
#   ./shodan_echo_v3.sh -f liste_ips.txt -n -w 8 -o rapport.json
#   ./shodan_echo_v3.sh -c 192.168.1.0/24 -n --whois --geo -o rapport.ndjson --fmt ndjson
# ==============================================================================

set -euo pipefail

# --- Couleurs et Formatage ---
CYAN='\033[1;36m'; YELLOW='\033[1;33m'; GREEN='\033[1;32m'
RED='\033[1;31m';  MAGENTA='\033[1;35m'; BLUE='\033[1;34m'
WHITE='\033[1;37m'; GREY='\033[0;37m'; NC='\033[0m'
BOLD='\033[1m'; DIM='\033[2m'

# --- Variables par défaut ---
TARGET=""
TARGET_FILE=""
TARGET_CIDR=""
STRATE="2026"
DELTA_MAX="0.65"
MA_DURATION="5"
OUTPUT_FILE=""
OUTPUT_FMT="json"       # json | ndjson | csv
USE_NRICH=false
USE_WHOIS=false
USE_GEO=false
USE_ABUSEIPDB=false
ABUSEIPDB_KEY=""
WORKERS=4
CACHE_DIR="${HOME}/.cache/shodan-echo"
CACHE_TTL=3600          # secondes (1h)
VERBOSE=false
QUIET=false
NO_MA=false
RATE_DELAY="0.3"        # délai inter-requêtes (secondes)
SEED_CORPUS="2026"      # graine du Corpus pour calcul Δ

# --- Statistiques globales ---
STAT_TOTAL=0
STAT_SCANNED=0
STAT_SKIPPED=0
STAT_CVE_TOTAL=0
STAT_GHOST_TOTAL=0
START_TIME=$(date +%s)

# --- Fichiers temporaires (nettoyés à la sortie) ---
TMP_DIR=$(mktemp -d)
TMP_RESULTS="${TMP_DIR}/results.ndjson"
TMP_LOCK="${TMP_DIR}/lock"
touch "$TMP_RESULTS" "$TMP_LOCK"

# ==============================================================================
# NETTOYAGE & SIGNAUX
# ==============================================================================
cleanup() {
    local code=${1:-0}
    [[ "$QUIET" == false ]] && echo -e "\n${DIM}[~] Nettoyage des fragments temporels...${NC}"
    rm -rf "$TMP_DIR"
    [[ $code -ne 0 ]] && echo -e "${RED}[!] Interruption du Programme. Que le Δ vous protège.${NC}"
    exit "$code"
}
trap 'cleanup 1' INT TERM
trap 'cleanup 0' EXIT

# ==============================================================================
# UTILITAIRES
# ==============================================================================
log_info()  { [[ "$QUIET" == false ]] && echo -e "${BLUE}[*]${NC} $*"; }
log_ok()    { [[ "$QUIET" == false ]] && echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { [[ "$QUIET" == false ]] && echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[✗]${NC} $*" >&2; }
log_debug() { [[ "$VERBOSE" == true ]] && echo -e "${GREY}[~]${NC} $*"; }

# Mutex léger via flock pour l'écriture concurrente
locked_append() {
    local file="$1"; local content="$2"
    (flock 200; echo "$content" >> "$file") 200>"${TMP_LOCK}"
}

# Timestamp ISO-8601
iso_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Durée en secondes depuis START_TIME
elapsed() { echo $(( $(date +%s) - START_TIME )); }

# Incrément atomique (compatible bash multi-process via fichier)
incr_stat() {
    local var_file="${TMP_DIR}/stat_${1}"
    (flock 201
        local v=0
        [[ -f "$var_file" ]] && v=$(cat "$var_file")
        echo $(( v + ${2:-1} )) > "$var_file"
    ) 201>"${TMP_LOCK}.stat"
}

read_stat() {
    local var_file="${TMP_DIR}/stat_${1}"
    [[ -f "$var_file" ]] && cat "$var_file" || echo 0
}

# ==============================================================================
# VALIDATION IP
# ==============================================================================
# Retourne : "public" | "private" | "loopback" | "multicast" | "reserved" | "invalid"
classify_ip() {
    local ip="$1"
    # Validation format
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "invalid"; return
    fi
    IFS='.' read -r a b c d <<< "$ip"
    # Vérification octets 0-255
    for oct in $a $b $c $d; do
        (( oct > 255 )) && { echo "invalid"; return; }
    done
    # Loopback
    (( a == 127 )) && { echo "loopback"; return; }
    # Multicast
    (( a >= 224 && a <= 239 )) && { echo "multicast"; return; }
    # Reserved / Broadcast
    (( a == 0 || a == 255 )) && { echo "reserved"; return; }
    # RFC 1918 – Privé
    (( a == 10 )) && { echo "private"; return; }
    (( a == 172 && b >= 16 && b <= 31 )) && { echo "private"; return; }
    (( a == 192 && b == 168 )) && { echo "private"; return; }
    # Link-local
    (( a == 169 && b == 254 )) && { echo "private"; return; }
    echo "public"
}

# ==============================================================================
# EXPANSION CIDR (sans dépendance externe)
# ==============================================================================
cidr_to_ips() {
    local cidr="$1"
    local ip_part="${cidr%/*}"
    local prefix="${cidr#*/}"

    IFS='.' read -r a b c d <<< "$ip_part"
    local ip_int=$(( (a<<24) | (b<<16) | (c<<8) | d ))
    local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
    local net=$(( ip_int & mask ))
    local broadcast=$(( net | (~mask & 0xFFFFFFFF) ))

    # Limite de sécurité : /16 max (65534 IPs)
    local count=$(( broadcast - net - 1 ))
    if (( count > 65534 )); then
        log_warn "CIDR /${prefix} trop large (${count} hôtes). Limite : /16."
        return 1
    fi

    for (( i = net + 1; i < broadcast; i++ )); do
        printf "%d.%d.%d.%d\n" \
            $(( (i>>24) & 0xFF )) $(( (i>>16) & 0xFF )) \
            $(( (i>>8)  & 0xFF )) $(( i & 0xFF ))
    done
}

# ==============================================================================
# CACHE
# ==============================================================================
cache_get() {
    local ip="$1" source="$2"
    local cf="${CACHE_DIR}/${ip//./_}_${source}.json"
    [[ ! -f "$cf" ]] && return 1
    local age=$(( $(date +%s) - $(stat -c%Y "$cf" 2>/dev/null || echo 0) ))
    (( age > CACHE_TTL )) && return 1
    cat "$cf"
}

cache_set() {
    local ip="$1" source="$2" data="$3"
    mkdir -p "$CACHE_DIR"
    echo "$data" > "${CACHE_DIR}/${ip//./_}_${source}.json"
}

# ==============================================================================
# CALCUL DELTA — v3 : Hash XOR 4 octets + seed du Corpus
# ==============================================================================
# Retourne un float dans [0.10 ; 0.95] de façon déterministe
calculer_delta() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    local seed_val=$(( SEED_CORPUS % 256 ))
    # XOR croisé des octets avec la graine
    local xor=$(( (a ^ b ^ c ^ d ^ seed_val) & 0xFF ))
    # Rotation de bits (shift cyclique 3 bits)
    local rot=$(( ((xor << 3) | (xor >> 5)) & 0xFF ))
    # Normalisation dans [0.10 ; 0.95]
    local delta
    delta=$(awk -v r="$rot" 'BEGIN { printf "%.3f", 0.10 + (r / 255.0) * 0.85 }')
    echo "$delta"
}

delta_color() {
    local d="$1"
    awk -v d="$d" -v g="${GREEN}" -v y="${YELLOW}" -v r="${RED}" \
        'BEGIN { if (d < 0.45) print g; else if (d < 0.70) print y; else print r }'
}

delta_label() {
    local d="$1"
    awk -v d="$d" 'BEGIN {
        if      (d < 0.30) print "STABLE"
        else if (d < 0.45) print "CALME"
        else if (d < 0.60) print "TROUBLE"
        else if (d < 0.75) print "TURBULENT"
        else               print "CRITIQUE"
    }'
}

# ==============================================================================
# PORTS FANTÔMES DU CORPUS — v3 : Logique étendue sur 4 octets
# ==============================================================================
analyser_ports_fantomes() {
    local ip="$1"
    local delta="$2"
    IFS='.' read -r a b c d <<< "$ip"
    local last=$d
    local sum=$(( a + b + c + d ))
    local xor=$(( a ^ b ^ c ^ d ))

    local ghost_count=0
    local ghost_json="[]"
    local ghost_tmp="${TMP_DIR}/ghosts_${ip//./_}.json"
    echo "[]" > "$ghost_tmp"

    append_ghost() {
        local port="$1" name="$2" sig="$3" severity="$4"
        ghost_count=$(( ghost_count + 1 ))
        local entry
        entry=$(jq -n --arg p "$port" --arg n "$name" \
                       --arg s "$sig" --arg sev "$severity" \
                '{port:$p, name:$n, signature:$s, severity:$sev}')
        jq ". + [$entry]" "$ghost_tmp" > "${ghost_tmp}.new" \
            && mv "${ghost_tmp}.new" "$ghost_tmp"

        local color=$YELLOW
        [[ "$severity" == "CRITIQUE" ]] && color=$RED
        [[ "$severity" == "STABLE" ]]   && color=$GREEN

        echo -e "       ${color}➜ Port ${port} : ${name}${NC}"
        echo -e "         ${DIM}Signature : ${sig}${NC}"
        echo -e "         ${GREY}Sévérité  : ${severity}${NC}"
    }

    echo -e "\n    ${MAGENTA}┌── RÉSONANCE DU CORPUS ─────────────────────────────┐${NC}"

    # Port 0 — Le Vide (delta < 0.25 : extrêmement rare)
    if awk -v d="$delta" 'BEGIN{exit !(d < 0.25)}'; then
        append_ghost "0" "Le Vide (Port Ontologique)" \
            "Ω∅•••void•••${xor}•••${sum}Ω" "CRITIQUE"
    fi

    # Port 3303 — Galet-Ancre (sum divisible par 7)
    if (( sum % 7 == 0 )); then
        append_ghost "3303" "Galet-Ancre (Bio-lithique)" \
            "Ω•galet•${sum}•ancré•Ω" "STABLE"
    fi

    # Port 7071 — Le Transept (xor == 0 : octets identiques deux à deux)
    if (( xor == 0 )); then
        append_ghost "7071" "Le Transept (Fenêtre 707s)" \
            "Ω=sym=•707•=${xor}=Ω" "TROUBLE"
    fi

    # Port 9877 — Faille du Jardinier (dernier octet pair)
    if (( last % 2 == 0 )); then
        append_ghost "9877" "Faille du Jardinier (Injection HFT)" \
            "Ω7d3c9a2f•raz•${last}Ω" "TURBULENT"
    fi

    # Port 11223 — Le Miroir (a == d : premier = dernier octet)
    if (( a == d )); then
        append_ghost "11223" "Le Miroir (Palindrome Réticulaire)" \
            "Ω•mirror•${a}↔${d}•Ω" "TROUBLE"
    fi

    # Port 14225 — Bande 17m BloodNet (multiple de 5)
    if (( last % 5 == 0 )); then
        append_ghost "14225" "Bande 17m (Diffusion BloodNet HF)" \
            "Ωlaguz•14.225MHz•${last}Ω" "TURBULENT"
    fi

    # Port 14400 — Le Trickster (xor == 144)
    if (( xor == 144 || xor == 72 || xor == 36 )); then
        append_ghost "14400" "Le Trickster (Port Noir / 144 symboles)" \
            "Ω144•trick•${xor}•Ω" "CRITIQUE"
    fi

    # Port 19999 — L'Écho Inversé (sum > 700)
    if (( sum > 700 )); then
        append_ghost "19999" "L'Écho Inversé (Harmonique Sombre)" \
            "Ωecho•inv•${sum}•∞Ω" "TURBULENT"
    fi

    # Port 31337 — L'Élite (b == c : deuxième = troisième octet)
    if (( b == c )); then
        append_ghost "31337" "L'Élite (Spectre Elite / e337)" \
            "Ω3lit3•${b}=${c}•Ω" "STABLE"
    fi

    # Port 44444 — Les Quatre Sceaux (tous octets > 44)
    if (( a > 44 && b > 44 && c > 44 && d > 44 )); then
        append_ghost "44444" "Les Quatre Sceaux (Quaternité Scellée)" \
            "Ω4×4•${a}|${b}|${c}|${d}•Ω" "CRITIQUE"
    fi

    # Port 65535 — Le Plafond (dernier octet == 255)
    if (( last == 255 )); then
        append_ghost "65535" "Le Plafond (Limite du Programme)" \
            "Ω0xFFFF•limit•${last}Ω" "CRITIQUE"
    fi

    if (( ghost_count == 0 )); then
        echo -e "       ${CYAN}∿ Résonance faible. Bruit de fond nominal du Programme.${NC}"
    fi

    echo -e "    ${MAGENTA}└── ${ghost_count} port(s) fantôme(s) détecté(s) ──────────────────────┘${NC}"

    # Retourne le JSON des ghosts et le count
    echo "$ghost_count"
    cat "$ghost_tmp"
}

# ==============================================================================
# ENRICHISSEMENT : NRICH
# ==============================================================================
enrichir_nrich() {
    local ip="$1"

    # Vérification cache
    local cached
    if cached=$(cache_get "$ip" "nrich"); then
        log_debug "Cache hit nrich pour ${ip}"
        echo "$cached"; return 0
    fi

    local tmp_ip; tmp_ip=$(mktemp)
    echo "$ip" > "$tmp_ip"

    local output
    output=$(timeout 10 nrich -o json "$tmp_ip" 2>/dev/null || true)
    rm -f "$tmp_ip"

    [[ -z "$output" || "$output" == "null" ]] && echo "{}" && return 0

    # Valider que c'est du JSON
    if echo "$output" | jq . &>/dev/null 2>&1; then
        cache_set "$ip" "nrich" "$output"
        echo "$output"
    else
        echo "{}"
    fi
}

# ==============================================================================
# ENRICHISSEMENT : WHOIS (structuré)
# ==============================================================================
enrichir_whois() {
    local ip="$1"

    local cached
    if cached=$(cache_get "$ip" "whois"); then
        log_debug "Cache hit whois pour ${ip}"
        echo "$cached"; return 0
    fi

    if ! command -v whois &>/dev/null; then
        echo '{"error":"whois non disponible"}'; return 0
    fi

    local raw
    raw=$(timeout 8 whois "$ip" 2>/dev/null || true)

    local netname org abuse country rir reg_date cidr
    netname=$(echo "$raw" | grep -iE '^netname:' | head -1 | awk -F: '{$1=""; print $0}' | xargs)
    org=$(echo "$raw" | grep -iE '^(org-name|orgname|organization):' | head -1 | awk -F: '{$1=""; print $0}' | xargs)
    abuse=$(echo "$raw" | grep -iE '^(abuse-mailbox|orgabuseemail):' | head -1 | awk -F: '{$1=""; print $0}' | xargs)
    country=$(echo "$raw" | grep -iE '^country:' | head -1 | awk -F: '{print $2}' | xargs)
    rir=$(echo "$raw" | grep -iE '^(source|aut-num):' | head -1 | awk -F: '{print $2}' | xargs)
    reg_date=$(echo "$raw" | grep -iE '^(regdate|created):' | head -1 | awk -F: '{$1=""; print $0}' | xargs)
    cidr=$(echo "$raw" | grep -iE '^(cidr|inetnum):' | head -1 | awk -F: '{$1=""; print $0}' | xargs)

    local result
    result=$(jq -n \
        --arg netname "$netname" --arg org "$org" --arg abuse "$abuse" \
        --arg country "$country" --arg rir "$rir" --arg reg_date "$reg_date" \
        --arg cidr "$cidr" \
        '{netname:$netname, org:$org, abuse_contact:$abuse,
          country:$country, rir:$rir, reg_date:$reg_date, cidr:$cidr}')

    cache_set "$ip" "whois" "$result"
    echo "$result"
}

# ==============================================================================
# ENRICHISSEMENT : DNS INVERSE (PTR)
# ==============================================================================
enrichir_dns() {
    local ip="$1"

    local cached
    if cached=$(cache_get "$ip" "dns"); then
        log_debug "Cache hit DNS pour ${ip}"
        echo "$cached"; return 0
    fi

    local ptr="N/A"
    if command -v dig &>/dev/null; then
        ptr=$(timeout 5 dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || true)
    elif command -v host &>/dev/null; then
        ptr=$(timeout 5 host "$ip" 2>/dev/null | grep 'domain name pointer' | awk '{print $NF}' | sed 's/\.$//' || true)
    fi

    [[ -z "$ptr" ]] && ptr="N/A"

    local result
    result=$(jq -n --arg ptr "$ptr" '{ptr:$ptr}')
    cache_set "$ip" "dns" "$result"
    echo "$result"
}

# ==============================================================================
# ENRICHISSEMENT : GÉOLOCALISATION (ip-api.com, sans clé)
# ==============================================================================
enrichir_geo() {
    local ip="$1"

    local cached
    if cached=$(cache_get "$ip" "geo"); then
        log_debug "Cache hit geo pour ${ip}"
        echo "$cached"; return 0
    fi

    if ! command -v curl &>/dev/null; then
        echo '{"error":"curl non disponible"}'; return 0
    fi

    local resp
    resp=$(timeout 8 curl -s \
        "http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting" \
        2>/dev/null || true)

    if [[ -z "$resp" ]] || ! echo "$resp" | jq -e '.status == "success"' &>/dev/null; then
        echo '{"status":"fail"}'; return 0
    fi

    local result
    result=$(echo "$resp" | jq '{
        country:      .country,
        country_code: .countryCode,
        region:       .regionName,
        city:         .city,
        lat:          .lat,
        lon:          .lon,
        isp:          .isp,
        org:          .org,
        asn:          .as,
        mobile:       .mobile,
        proxy:        .proxy,
        hosting:      .hosting
    }')

    cache_set "$ip" "geo" "$result"
    echo "$result"
}

# ==============================================================================
# ENRICHISSEMENT : ABUSEIPDB
# ==============================================================================
enrichir_abuseipdb() {
    local ip="$1"

    [[ -z "$ABUSEIPDB_KEY" ]] && echo '{}' && return 0

    local cached
    if cached=$(cache_get "$ip" "abuseipdb"); then
        echo "$cached"; return 0
    fi

    local resp
    resp=$(timeout 8 curl -s -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=${ip}" \
        -d "maxAgeInDays=90" \
        -H "Key: ${ABUSEIPDB_KEY}" \
        -H "Accept: application/json" 2>/dev/null || true)

    if [[ -z "$resp" ]] || ! echo "$resp" | jq -e '.data' &>/dev/null; then
        echo '{}'; return 0
    fi

    local result
    result=$(echo "$resp" | jq '.data | {
        abuse_confidence: .abuseConfidenceScore,
        total_reports:    .totalReports,
        last_reported:    .lastReportedAt,
        is_tor:           .isTor,
        is_public:        .isPublic,
        usage_type:       .usageType,
        domain:           .domain
    }')

    cache_set "$ip" "abuseipdb" "$result"
    echo "$result"
}

# ==============================================================================
# AFFICHAGE CVSS
# ==============================================================================
cvss_badge() {
    local score="$1"
    awk -v s="$score" -v r="${RED}" -v y="${YELLOW}" -v g="${GREEN}" -v nc="${NC}" 'BEGIN {
        if      (s >= 9.0) printf r"[CRITIQUE %.1f]"nc, s
        else if (s >= 7.0) printf r"[ÉLEVÉ %.1f]"nc, s
        else if (s >= 4.0) printf y"[MOYEN %.1f]"nc, s
        else               printf g"[FAIBLE %.1f]"nc, s
    }'
}

# ==============================================================================
# MOTEUR PRINCIPAL DE SCAN
# ==============================================================================
scanner_echo() {
    local ip="$1"
    local worker_id="${2:-0}"
    local sep="  "

    incr_stat "total"

    # Classification IP
    local ip_class
    ip_class=$(classify_ip "$ip")

    if [[ "$ip_class" == "invalid" ]]; then
        log_warn "IP invalide ignorée : ${ip}"
        incr_stat "skipped"
        return 0
    fi

    if [[ "$ip_class" == "loopback" || "$ip_class" == "multicast" || "$ip_class" == "reserved" ]]; then
        log_warn "${ip} ignorée (${ip_class})"
        incr_stat "skipped"
        return 0
    fi

    # Calcul Δ
    local delta
    delta=$(calculer_delta "$ip")
    local dc
    dc=$(delta_color "$delta")
    local dl
    dl=$(delta_label "$delta")

    # En-tête de l'IP
    local scope_tag=""
    [[ "$ip_class" == "private" ]] && scope_tag=" ${YELLOW}[PRIVÉE]${NC}"

    echo -e "\n${MAGENTA}╔══════════════════════════════════════════════════════════╗${NC}"
    printf "${MAGENTA}║${NC}  ${BOLD}%-55s${NC}${MAGENTA}║${NC}\n" "CIBLE : ${ip}${scope_tag}"
    printf "${MAGENTA}║${NC}  Δ = ${dc}%-8s${NC}  %-9s  Strate: %-12s  W#%-2s ${MAGENTA}║${NC}\n" \
           "$delta" "[$dl]" "$STRATE" "$worker_id"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════╝${NC}"

    # Seuil Δ
    if awk -v d="$delta" -v m="$DELTA_MAX" 'BEGIN{exit !(d > m)}'; then
        echo -e "${sep}${RED}⚠️  Δ trop élevé (${delta} > ${DELTA_MAX}). Risque Prométhée — skip.${NC}"
        incr_stat "skipped"
        locked_append "$TMP_RESULTS" \
            "$(jq -n --arg ip "$ip" --arg d "$delta" \
                '{ip:$ip,delta:$d,status:"skipped_delta"}')"
        return 0
    fi

    # IP privée : avertissement (on continue si demandé)
    if [[ "$ip_class" == "private" ]]; then
        log_warn "${ip} est une adresse privée. L'enrichissement NRICH/GEO sera limité."
    fi

    # ── Rate limit ──
    sleep "$RATE_DELAY"

    # ── Enrichissements ──
    local nrich_data="{}" whois_data="{}" dns_data="{}" geo_data="{}" abuse_data="{}"

    if [[ "$USE_NRICH" == true && "$ip_class" == "public" ]]; then
        echo -e "${sep}${BLUE}📡 Interrogation NRICH...${NC}"
        nrich_data=$(enrichir_nrich "$ip")
        local asn org country cve_arr cve_count
        asn=$(echo "$nrich_data" | jq -r '.asn.number // "N/A"')
        org=$(echo "$nrich_data" | jq -r '.asn.organization // "N/A"')
        country=$(echo "$nrich_data" | jq -r '.location.country // "N/A"')
        cve_arr=$(echo "$nrich_data" | jq -c '.cve // []')
        cve_count=$(echo "$cve_arr" | jq 'length')

        echo -e "${sep}${BLUE}┌─ NRICH${NC}"
        echo -e "${sep}${BLUE}│${NC} ASN     : AS${asn}"
        echo -e "${sep}${BLUE}│${NC} Org     : ${org}"
        echo -e "${sep}${BLUE}│${NC} Pays    : ${country}"
        echo -e "${sep}${BLUE}│${NC} CVEs    : ${cve_count}"

        if (( cve_count > 0 )); then
            incr_stat "cves" "$cve_count"
            echo -e "${sep}${BLUE}│${NC} ${RED}Vulnérabilités :${NC}"
            echo "$cve_arr" | jq -r '.[] | "\(.id) \(.cvss // "?")"' | while read -r cve_id cvss; do
                local badge
                badge=$(cvss_badge "${cvss:-0}")
                echo -e "${sep}${BLUE}│${NC}   ${badge} ${WHITE}${cve_id}${NC}"
            done
        fi

        local open_ports
        open_ports=$(echo "$nrich_data" | jq -r \
            '[.ports[]? | tostring] | join(", ")' 2>/dev/null || true)
        [[ -n "$open_ports" ]] && \
            echo -e "${sep}${BLUE}│${NC} Ports   : ${GREEN}${open_ports}${NC}"

        echo -e "${sep}${BLUE}└──────${NC}"
    fi

    if [[ "$USE_WHOIS" == true ]]; then
        echo -e "${sep}${CYAN}🔍 Interrogation WHOIS...${NC}"
        whois_data=$(enrichir_whois "$ip")
        local w_netname w_org w_abuse w_rir w_cidr
        w_netname=$(echo "$whois_data" | jq -r '.netname // "N/A"')
        w_org=$(echo "$whois_data" | jq -r '.org // "N/A"')
        w_abuse=$(echo "$whois_data" | jq -r '.abuse_contact // "N/A"')
        w_rir=$(echo "$whois_data" | jq -r '.rir // "N/A"')
        w_cidr=$(echo "$whois_data" | jq -r '.cidr // "N/A"')

        echo -e "${sep}${CYAN}┌─ WHOIS${NC}"
        echo -e "${sep}${CYAN}│${NC} Réseau  : ${w_netname}  (${w_cidr})"
        echo -e "${sep}${CYAN}│${NC} Org     : ${w_org}"
        echo -e "${sep}${CYAN}│${NC} Abuse   : ${w_abuse}"
        echo -e "${sep}${CYAN}│${NC} RIR     : ${w_rir}"
        echo -e "${sep}${CYAN}└──────${NC}"

        # DNS PTR
        echo -e "${sep}${CYAN}🔁 Résolution DNS inverse...${NC}"
        dns_data=$(enrichir_dns "$ip")
        local ptr
        ptr=$(echo "$dns_data" | jq -r '.ptr // "N/A"')
        echo -e "${sep}${CYAN}   PTR : ${GREEN}${ptr}${NC}"
    fi

    if [[ "$USE_GEO" == true && "$ip_class" == "public" ]]; then
        echo -e "${sep}${GREEN}🌍 Géolocalisation...${NC}"
        geo_data=$(enrichir_geo "$ip")
        local g_country g_city g_isp g_lat g_lon g_proxy g_hosting
        g_country=$(echo "$geo_data" | jq -r '.country // "N/A"')
        g_city=$(echo "$geo_data" | jq -r '.city // "N/A"')
        g_isp=$(echo "$geo_data" | jq -r '.isp // "N/A"')
        g_lat=$(echo "$geo_data" | jq -r '.lat // "N/A"')
        g_lon=$(echo "$geo_data" | jq -r '.lon // "N/A"')
        g_proxy=$(echo "$geo_data" | jq -r '.proxy // false')
        g_hosting=$(echo "$geo_data" | jq -r '.hosting // false')

        local proxy_flag=""
        [[ "$g_proxy" == "true" ]] && proxy_flag=" ${RED}[PROXY]${NC}"
        [[ "$g_hosting" == "true" ]] && proxy_flag+=" ${YELLOW}[HOSTING]${NC}"

        echo -e "${sep}${GREEN}┌─ GEO${NC}"
        echo -e "${sep}${GREEN}│${NC} Localité : ${g_city}, ${g_country}${proxy_flag}"
        echo -e "${sep}${GREEN}│${NC} Coords   : ${g_lat}, ${g_lon}"
        echo -e "${sep}${GREEN}│${NC} ISP      : ${g_isp}"
        echo -e "${sep}${GREEN}└──────${NC}"
    fi

    if [[ "$USE_ABUSEIPDB" == true && "$ip_class" == "public" ]]; then
        echo -e "${sep}${RED}🚨 Vérification AbuseIPDB...${NC}"
        abuse_data=$(enrichir_abuseipdb "$ip")
        local ab_score ab_reports ab_domain ab_type
        ab_score=$(echo "$abuse_data" | jq -r '.abuse_confidence // "N/A"')
        ab_reports=$(echo "$abuse_data" | jq -r '.total_reports // 0')
        ab_domain=$(echo "$abuse_data" | jq -r '.domain // "N/A"')
        ab_type=$(echo "$abuse_data" | jq -r '.usage_type // "N/A"')

        local score_color=$GREEN
        [[ "$ab_score" =~ ^[0-9]+$ ]] && (( ab_score > 50 )) && score_color=$YELLOW
        [[ "$ab_score" =~ ^[0-9]+$ ]] && (( ab_score > 80 )) && score_color=$RED

        echo -e "${sep}${RED}┌─ ABUSEIPDB${NC}"
        echo -e "${sep}${RED}│${NC} Confiance abus : ${score_color}${ab_score}%${NC}"
        echo -e "${sep}${RED}│${NC} Rapports       : ${ab_reports}"
        echo -e "${sep}${RED}│${NC} Domaine        : ${ab_domain}"
        echo -e "${sep}${RED}│${NC} Usage          : ${ab_type}"
        echo -e "${sep}${RED}└──────${NC}"
    fi

    # ── Ports Fantômes ──
    local ghost_out ghost_count ghost_json
    # On capture les deux lignes de sortie : count puis json
    ghost_out=$(analyser_ports_fantomes "$ip" "$delta")
    ghost_count=$(echo "$ghost_out" | head -1)
    ghost_json=$(echo "$ghost_out" | tail -n +2)
    incr_stat "ghosts" "$ghost_count"

    incr_stat "scanned"

    # ── Construction entrée JSON ──
    local ts
    ts=$(iso_ts)
    local entry
    entry=$(jq -n \
        --arg ip "$ip" \
        --arg ts "$ts" \
        --arg strate "$STRATE" \
        --arg delta "$delta" \
        --arg delta_label "$dl" \
        --arg ip_class "$ip_class" \
        --argjson nrich_data "$nrich_data" \
        --argjson whois_data "$whois_data" \
        --argjson dns_data "$dns_data" \
        --argjson geo_data "$geo_data" \
        --argjson abuse_data "$abuse_data" \
        --argjson ghost_ports "$ghost_json" \
        --argjson ghost_count "$ghost_count" \
        '{
            ip:          $ip,
            timestamp:   $ts,
            strate:      $strate,
            delta:       ($delta | tonumber),
            delta_label: $delta_label,
            ip_class:    $ip_class,
            nrich:       $nrich_data,
            whois:       $whois_data,
            dns:         $dns_data,
            geo:         $geo_data,
            abuse:       $abuse_data,
            ghost_ports: { count: $ghost_count, ports: $ghost_ports }
        }')

    locked_append "$TMP_RESULTS" "$entry"
}

# ==============================================================================
# EXPORT FINAL
# ==============================================================================
exporter() {
    local total_scanned
    total_scanned=$(read_stat "scanned")
    local total_skipped
    total_skipped=$(read_stat "skipped")
    local total_cves
    total_cves=$(read_stat "cves")
    local total_ghosts
    total_ghosts=$(read_stat "ghosts")
    local elapsed_s
    elapsed_s=$(elapsed)

    # Résumé terminal
    echo -e "\n${MAGENTA}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}  ${BOLD}RÉSUMÉ DE SESSION${NC}                                      ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "${MAGENTA}║${NC}  IPs analysées  : ${GREEN}%-5s${NC}  IPs ignorées : ${YELLOW}%-5s${NC}       ${MAGENTA}║${NC}\n" \
           "$total_scanned" "$total_skipped"
    printf "${MAGENTA}║${NC}  CVEs totales   : ${RED}%-5s${NC}  Ports fantômes: ${CYAN}%-5s${NC}       ${MAGENTA}║${NC}\n" \
           "$total_cves" "$total_ghosts"
    printf "${MAGENTA}║${NC}  Durée          : ${WHITE}%ss${NC}  Strate: %-14s       ${MAGENTA}║${NC}\n" \
           "$elapsed_s" "$STRATE"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════╝${NC}"

    [[ -z "$OUTPUT_FILE" ]] && return

    local meta
    meta=$(jq -n \
        --arg ts "$(iso_ts)" \
        --arg strate "$STRATE" \
        --arg delta_max "$DELTA_MAX" \
        --argjson scanned "$total_scanned" \
        --argjson skipped "$total_skipped" \
        --argjson cves "$total_cves" \
        --argjson ghosts "$total_ghosts" \
        --argjson elapsed "$elapsed_s" \
        '{
            generated_at: $ts,
            strate:       $strate,
            delta_max:    ($delta_max | tonumber),
            stats: {
                scanned: $scanned,
                skipped: $skipped,
                total_cves: $cves,
                total_ghost_ports: $ghosts,
                elapsed_seconds: $elapsed
            }
        }')

    case "$OUTPUT_FMT" in
        json)
            # Tableau JSON valide avec métadonnées
            {
                echo '{'
                echo "  \"meta\": $(echo "$meta" | jq '.'),"
                echo '  "results": ['
                local first=true
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    if $first; then
                        echo "    $line"
                        first=false
                    else
                        echo "    ,$line"
                    fi
                done < "$TMP_RESULTS"
                echo '  ]'
                echo '}'
            } | jq '.' > "$OUTPUT_FILE"
            echo -e "${GREEN}💾 JSON exporté : ${OUTPUT_FILE}${NC}"
            ;;

        ndjson)
            # Une entrée JSON par ligne (streaming-friendly)
            cp "$TMP_RESULTS" "$OUTPUT_FILE"
            echo -e "${GREEN}💾 NDJSON exporté : ${OUTPUT_FILE}${NC}"
            ;;

        csv)
            # CSV : ip, delta, country, asn, org, cve_count, ghost_count
            {
                echo "ip,delta,delta_label,ip_class,country,asn,org,cve_count,ghost_count,ptr,timestamp"
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    echo "$line" | jq -r '[
                        .ip,
                        (.delta | tostring),
                        .delta_label,
                        .ip_class,
                        (.nrich.location.country // .geo.country // "N/A"),
                        (.nrich.asn.number // "N/A"),
                        (.nrich.asn.organization // .whois.org // "N/A"),
                        ((.nrich.cve // []) | length | tostring),
                        (.ghost_ports.count | tostring),
                        (.dns.ptr // "N/A"),
                        .timestamp
                    ] | @csv'
                done < "$TMP_RESULTS"
            } > "$OUTPUT_FILE"
            echo -e "${GREEN}💾 CSV exporté : ${OUTPUT_FILE}${NC}"
            ;;
    esac
}

# ==============================================================================
# AIDE
# ==============================================================================
usage() {
    echo -e "${MAGENTA}"
    echo "  SHODAN-ECHO v3.0 — Enrichissement Réseau Multi-Sources"
    echo -e "${NC}"
    echo -e "  ${BOLD}Cibles${NC}"
    echo -e "    -t, --target <IP>       IP unique"
    echo -e "    -f, --file   <fichier>  Liste d'IPs (une par ligne)"
    echo -e "    -c, --cidr   <CIDR>     Plage réseau (ex: 10.0.0.0/24, max /16)"
    echo ""
    echo -e "  ${BOLD}Enrichissement${NC}"
    echo -e "    -n, --nrich             Activer nrich (Shodan)"
    echo -e "    -w2,--whois             Activer whois + DNS inverse"
    echo -e "    -g, --geo               Activer la géolocalisation (ip-api.com)"
    echo -e "    -A, --abuseipdb <KEY>   Activer AbuseIPDB (clé API requise)"
    echo ""
    echo -e "  ${BOLD}Performance${NC}"
    echo -e "    -w, --workers <N>       Parallélisme [défaut: 4]"
    echo -e "    -r, --rate <sec>        Délai inter-requêtes [défaut: 0.3s]"
    echo -e "        --no-cache          Désactiver le cache"
    echo -e "        --cache-ttl <sec>   TTL cache [défaut: 3600]"
    echo ""
    echo -e "  ${BOLD}Corpus${NC}"
    echo -e "    -s, --strate <annee>    Strate temporelle [défaut: 2026]"
    echo -e "    -d, --delta  <float>    Seuil Δ maximum [défaut: 0.65]"
    echo -e "    -m, --ma     <sec>      Durée du Silence Structuré [défaut: 5]"
    echo -e "        --no-ma             Sauter le protocole MA"
    echo -e "        --seed   <N>        Graine du Corpus [défaut: 2026]"
    echo ""
    echo -e "  ${BOLD}Sortie${NC}"
    echo -e "    -o, --output <fichier>  Fichier de rapport"
    echo -e "        --fmt  <format>     Format : json | ndjson | csv [défaut: json]"
    echo -e "    -v, --verbose           Mode verbeux"
    echo -e "    -q, --quiet             Mode silencieux"
    echo -e "    -h, --help              Cette aide"
    echo ""
    echo -e "  ${BOLD}Exemples${NC}"
    echo -e "    $0 -t 8.8.8.8 -n -g --whois"
    echo -e "    $0 -f ips.txt -n -g -w 8 -o rapport.json"
    echo -e "    $0 -c 203.0.113.0/24 -n --fmt ndjson -o out.ndjson"
    exit 1
}

# ==============================================================================
# PARSING DES ARGUMENTS
# ==============================================================================
NO_CACHE=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -t|--target)    TARGET="$2"; shift ;;
        -f|--file)      TARGET_FILE="$2"; shift ;;
        -c|--cidr)      TARGET_CIDR="$2"; shift ;;
        -s|--strate)    STRATE="$2"; shift ;;
        -d|--delta)     DELTA_MAX="$2"; shift ;;
        -m|--ma)        MA_DURATION="$2"; shift ;;
        --no-ma)        NO_MA=true ;;
        -n|--nrich)     USE_NRICH=true ;;
        -w2|--whois)    USE_WHOIS=true ;;
        -g|--geo)       USE_GEO=true ;;
        -A|--abuseipdb) USE_ABUSEIPDB=true; ABUSEIPDB_KEY="${2:-}"; shift ;;
        -w|--workers)   WORKERS="$2"; shift ;;
        -r|--rate)      RATE_DELAY="$2"; shift ;;
        --no-cache)     NO_CACHE=true ;;
        --cache-ttl)    CACHE_TTL="$2"; shift ;;
        --seed)         SEED_CORPUS="$2"; shift ;;
        -o|--output)    OUTPUT_FILE="$2"; shift ;;
        --fmt)          OUTPUT_FMT="$2"; shift ;;
        -v|--verbose)   VERBOSE=true ;;
        -q|--quiet)     QUIET=true ;;
        -h|--help)      usage ;;
        *) log_err "Paramètre inconnu: $1"; usage ;;
    esac
    shift
done

# Validation : au moins une cible
if [[ -z "$TARGET" && -z "$TARGET_FILE" && -z "$TARGET_CIDR" ]]; then
    log_err "Aucune cible spécifiée. Utilisez -t, -f ou -c."
    usage
fi

# Cache désactivé
[[ "$NO_CACHE" == true ]] && CACHE_TTL=0

# ==============================================================================
# VÉRIFICATION DES DÉPENDANCES
# ==============================================================================
check_deps() {
    local missing=()

    ! command -v jq   &>/dev/null && missing+=("jq")
    ! command -v bc   &>/dev/null && missing+=("bc")
    ! command -v awk  &>/dev/null && missing+=("awk")

    [[ "$USE_NRICH" == true ]] && ! command -v nrich  &>/dev/null && {
        log_warn "nrich non trouvé. Mode simulation NRICH."
        log_warn "➜ https://gitlab.com/shodan-public/nrich"
        USE_NRICH=false
    }
    [[ "$USE_WHOIS" == true ]] && ! command -v whois  &>/dev/null && {
        log_warn "whois non trouvé — enrichissement WHOIS désactivé."
        USE_WHOIS=false
    }
    [[ "$USE_GEO" == true ]]   && ! command -v curl   &>/dev/null && {
        log_warn "curl non trouvé — géolocalisation désactivée."
        USE_GEO=false
    }
    [[ "$USE_ABUSEIPDB" == true ]] && ! command -v curl &>/dev/null && {
        log_warn "curl non trouvé — AbuseIPDB désactivé."
        USE_ABUSEIPDB=false
    }

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_err "Dépendances manquantes : ${missing[*]}"
        log_err "Installez-les (ex: sudo apt install ${missing[*]})"
        exit 1
    fi
}

# ==============================================================================
# PROTOCOLE MA
# ==============================================================================
activer_ma() {
    [[ "$NO_MA" == true || "$QUIET" == true ]] && return
    echo -e "\n${CYAN}[*] Initialisation du protocole MA (Silence Structuré)...${NC}"
    echo -e "${CYAN}[*] Désarmement des Glottophages en cours.${NC}"
    for (( i=MA_DURATION; i>0; i-- )); do
        echo -ne "\r${YELLOW}⏳ Ma actif : ${i}s restantes... ∿∿∿${NC}"
        sleep 1
    done
    echo -e "\r${GREEN}✅ Ma complété. Fenêtre d'interférence ouverte.              ${NC}\n"
}

# ==============================================================================
# BANNIÈRE
# ==============================================================================
banniere() {
    [[ "$QUIET" == true ]] && return
    echo -e "${MAGENTA}"
    echo "  ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗  ██╗"
    echo "  ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗ ██║"
    echo "  ███████╗███████║██║   ██║██║  ██║███████║██╔██╗██║"
    echo "  ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚████║"
    echo "  ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚███║"
    echo "  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚══╝"
    echo "  ███████╗ ██████╗██╗  ██╗ ██████╗"
    echo "  ██╔════╝██╔════╝██║  ██║██╔═══██╗"
    echo "  █████╗  ██║     ███████║██║   ██║"
    echo "  ██╔══╝  ██║     ██╔══██║██║   ██║"
    echo "  ███████╗╚██████╗██║  ██║╚██████╔╝"
    echo "  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝"
    echo -e "  v3.0 (2026) — '${DIM}Le Δ ne ment pas. C'est le regard qui tremble.${NC}${MAGENTA}'${NC}\n"

    local sources=""
    [[ "$USE_NRICH"     == true ]] && sources+="NRICH "
    [[ "$USE_WHOIS"     == true ]] && sources+="WHOIS/DNS "
    [[ "$USE_GEO"       == true ]] && sources+="GEO "
    [[ "$USE_ABUSEIPDB" == true ]] && sources+="ABUSEIPDB "
    [[ -z "$sources" ]] && sources="Simulation (aucune source active)"

    echo -e "${MAGENTA}  Strate     : ${WHITE}${STRATE}${NC}"
    echo -e "${MAGENTA}  Δ max      : ${WHITE}${DELTA_MAX}${NC}"
    echo -e "${MAGENTA}  Workers    : ${WHITE}${WORKERS}${NC}"
    echo -e "${MAGENTA}  Sources    : ${WHITE}${sources}${NC}"
    echo -e "${MAGENTA}  Cache TTL  : ${WHITE}${CACHE_TTL}s${NC}  (${CACHE_DIR})"
    echo -e "${MAGENTA}  Format     : ${WHITE}${OUTPUT_FMT}${NC}\n"
}

# ==============================================================================
# POOL DE WORKERS (parallélisme bash)
# ==============================================================================
# Exporte les variables et fonctions nécessaires aux sous-shells
export -f scanner_echo calculer_delta delta_color delta_label classify_ip
export -f enrichir_nrich enrichir_whois enrichir_dns enrichir_geo enrichir_abuseipdb
export -f analyser_ports_fantomes cvss_badge cache_get cache_set
export -f log_info log_ok log_warn log_err log_debug incr_stat read_stat locked_append iso_ts

export TMP_DIR TMP_RESULTS TMP_LOCK
export STRATE DELTA_MAX RATE_DELAY CACHE_DIR CACHE_TTL SEED_CORPUS
export USE_NRICH USE_WHOIS USE_GEO USE_ABUSEIPDB ABUSEIPDB_KEY
export VERBOSE QUIET
export CYAN YELLOW GREEN RED MAGENTA BLUE WHITE GREY NC BOLD DIM

run_pool() {
    local ip_list_file="$1"
    local total_ips
    total_ips=$(wc -l < "$ip_list_file")

    log_info "Lancement du scan : ${total_ips} cible(s) — ${WORKERS} worker(s)"

    # xargs parallèle : chaque IP dans un sous-shell
    # -P = workers, -L 1 = 1 ligne par invocation
    cat "$ip_list_file" | xargs -P "$WORKERS" -L 1 -I{} \
        bash -c 'scanner_echo "$1" "${BASHPID}"' _ {}
}

# ==============================================================================
# PROGRAMME PRINCIPAL
# ==============================================================================
main() {
    check_deps
    banniere
    activer_ma

    mkdir -p "$CACHE_DIR"

    # Construction de la liste d'IPs à traiter
    local ip_list_file="${TMP_DIR}/ip_list.txt"
    touch "$ip_list_file"

    if [[ -n "$TARGET" ]]; then
        echo "$TARGET" >> "$ip_list_file"
    fi

    if [[ -n "$TARGET_FILE" ]]; then
        if [[ ! -f "$TARGET_FILE" ]]; then
            log_err "Fichier introuvable : ${TARGET_FILE}"
            exit 1
        fi
        # Filtrer les commentaires et lignes vides
        grep -vE '^\s*(#|$)' "$TARGET_FILE" >> "$ip_list_file"
    fi

    if [[ -n "$TARGET_CIDR" ]]; then
        log_info "Expansion CIDR : ${TARGET_CIDR}"
        cidr_to_ips "$TARGET_CIDR" >> "$ip_list_file"
    fi

    local ip_count
    ip_count=$(wc -l < "$ip_list_file")

    if (( ip_count == 0 )); then
        log_err "Liste d'IPs vide après traitement."
        exit 1
    fi

    # Déduplication
    sort -u "$ip_list_file" -o "$ip_list_file"
    local uniq_count
    uniq_count=$(wc -l < "$ip_list_file")
    (( uniq_count < ip_count )) && \
        log_warn "$((ip_count - uniq_count)) doublon(s) éliminé(s)"

    # Scan
    run_pool "$ip_list_file"

    # Export
    exporter

    echo -e "\n${MAGENTA}••• Session ${STRATE} terminée. Que le Δ vous guide. •••${NC}\n"
}

main
