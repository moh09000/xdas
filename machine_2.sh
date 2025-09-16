#!/usr/bin/env bash

# Configuration
OUTPUT_DIR="subdomains"
TARGETS_FILE="targets.txt"
FINAL_OUTPUT_DIR="results"

BLOCKED_EXTENSIONS=(
    ".jpg" ".jpeg" ".png" ".gif" ".pdf" ".svg" ".json"
    ".css" ".js" ".webp" ".woff" ".woff2" ".eot" ".ttf" ".otf" ".mp4" ".txt"
)
PARAM_PLACEHOLDER="FUZZ"
SUBBATCH_SIZE=20
TOOLS=("gau" "waybackurls" "katana")
MAX_CONCURRENT_TOOLS=3
REQUEST_DELAY=0.1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}[-] Missing dependency: $1${NC}"
        exit 1
    fi
}

setup_environment() {
    mkdir -p "$OUTPUT_DIR" "$FINAL_OUTPUT_DIR"
    if [ ! -f "$TARGETS_FILE" ]; then
        echo -e "${RED}[-] $TARGETS_FILE not found.${NC}"
        echo "example.com" > "$TARGETS_FILE"
        echo -e "${YELLOW}[!] Added placeholder. Edit $TARGETS_FILE to add targets.${NC}"
        exit 1
    fi
    rm -f "$OUTPUT_DIR"/{allsubs.txt,live_https.txt,live_subs.txt}
}

clean_urls() {
    sed -E 's|https?://||g; s|:[0-9]+||g' "$OUTPUT_DIR/live_https.txt" | sort -u > "$OUTPUT_DIR/live_subs.txt"
}

collect_subdomains() {
    echo -e "${BLUE}[+] Collecting subdomains...${NC}"
    TMP="$OUTPUT_DIR/tmp"
    mkdir -p "$TMP"

    subfinder -dL "$TARGETS_FILE" -silent -o "$TMP/subfinder.txt"
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        amass enum -passive -d "$d" -o "$TMP/amass_$d.txt"
        assetfinder --subs-only "$d" >> "$TMP/assetfinder.txt"
        curl -s "https://crt.sh/?q=%25.$d&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$TMP/crtsh.txt"
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.$d/*&output=txt&fl=original" \
            | sed -E 's_https?://([^/]+)/.*_\1_' | sort -u >> "$TMP/wayback.txt"
    done < "$TARGETS_FILE"

    cat "$TMP"/*.txt | sort -u > "$OUTPUT_DIR/allsubs.txt"
    rm -rf "$TMP"

    cat "$OUTPUT_DIR/allsubs.txt" | httprobe | tee "$OUTPUT_DIR/live_https.txt"
    clean_urls
    echo -e "${GREEN}[+] Subdomain collection complete.${NC}"
}

filter_urls() {
    local url
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local blocked=0
        for ext in "${BLOCKED_EXTENSIONS[@]}"; do
            [[ "$url" == *"$ext"* ]] && blocked=1 && break
        done
        [[ $blocked -eq 0 ]] && echo "$url"
    done
}

clean_params() {
    local url="$1"
    [[ "$url" != *"?"* ]] && echo "$url" && return
    local base="${url%%\?*}" query="${url#*\?}"
    declare -A params
    IFS='&' read -ra pairs <<< "$query"
    for p in "${pairs[@]}"; do
        k="${p%%=*}"
        params["$k"]="$PARAM_PLACEHOLDER"
    done
    local q=""
    for k in "${!params[@]}"; do
        [[ -n "$q" ]] && q+="&"
        q+="$k=${params[$k]}"
    done
    echo "$base?$q"
}

process_subbatch() {
    local subs=("$@") tmp=$(mktemp)
    printf '%s\n' "${subs[@]}" > "$tmp"
    local outputs=()
    gau --threads 5 --subs <"$tmp" >"${tmp}_gau" 2>/dev/null &
    waybackurls <"$tmp" >"${tmp}_wayback" 2>/dev/null &
    katana -jc -kf -d 3 -silent -c 5 <"$tmp" >"${tmp}_katana" 2>/dev/null &
    wait
    outputs+=("${tmp}_gau" "${tmp}_wayback" "${tmp}_katana")
    for o in "${outputs[@]}"; do
        while IFS= read -r url; do
            cleaned=$(clean_params "$url")
            [[ -n "$cleaned" ]] && echo "$cleaned"
        done < <(filter_urls <"$o")
        rm "$o"
    done
    rm "$tmp"
}

collect_urls() {
    local input="$OUTPUT_DIR/live_subs.txt"
    local output="$FINAL_OUTPUT_DIR/all_urls.txt"
    [[ ! -s "$input" ]] && echo -e "${RED}[-] No live subdomains.${NC}" && exit 1
    mapfile -t subs <"$input"
    >"$output"
    for ((i=0;i<${#subs[@]};i+=SUBBATCH_SIZE)); do
        batch=("${subs[@]:i:SUBBATCH_SIZE}")
        process_subbatch "${batch[@]}" >>"$output"
    done
    echo -e "${GREEN}[+] URL collection complete. Output: $output${NC}"
}

# --- Main Menu ---
echo -e "${GREEN}=== Automated Recon Pipeline ===${NC}"
check_dependency "subfinder"
check_dependency "httprobe"
for t in "${TOOLS[@]}"; do check_dependency "$t"; done
setup_environment

echo -e "${YELLOW}Choose an option:${NC}"
echo "1) Collect subdomains"
echo "2) Collect URLs"
echo "3) Run both"
read -rp "Enter choice [1-3]: " choice

case "$choice" in
  1) collect_subdomains ;;
  2) collect_urls ;;
  3) collect_subdomains; collect_urls ;;
  *) echo -e "${RED}Invalid choice. Exiting.${NC}"; exit 1 ;;
esac

echo -e "${GREEN}[+] Done. Exiting.${NC}"