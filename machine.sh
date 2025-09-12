#!/usr/bin/env bash

# Configuration for both parts
OUTPUT_DIR="subdomains"
TARGETS_FILE="targets.txt"
FINAL_OUTPUT_DIR="results"

# URL Collection Configuration
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

# --- Subdomain Collection Functions ---

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[-] Error: $1 not installed. Please install it first.${NC}"
        echo -e "${YELLOW}[!] Try: sudo apt install subfinder && go install github.com/tomnomnom/httprobe@latest${NC}"
        exit 1
    fi
}

setup_environment() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$FINAL_OUTPUT_DIR"
    if [ ! -f "$TARGETS_FILE" ]; then
        echo -e "${RED}[-] Error: $TARGETS_FILE not found.${NC}"
        echo -e "${YELLOW}[!] Create it and add target domains (one per line):${NC}"
        echo -e "example.com\ngithub.com\nacme.org" > "$TARGETS_FILE"
        exit 1
    fi
    rm -f "$OUTPUT_DIR/allsubs.txt" "$OUTPUT_DIR/live_https.txt" "$OUTPUT_DIR/live_subs.txt"
}

clean_urls() {
    echo -e "${GREEN}[+] Cleaning and deduplicating URLs...${NC}"
    sed -E 's|https?://||g; s|:[0-9]+||g' "$OUTPUT_DIR/live_https.txt" | sort -u > "$OUTPUT_DIR/live_subs.txt"
}

collect_subdomains() {
    echo -e "${BLUE}[+] Starting subdomain collection...${NC}"
    
    # Subdomain enumeration
    echo -e "${GREEN}[+] Running Subfinder...${NC}"
    subfinder -dL "$TARGETS_FILE" -all -silent -o "$OUTPUT_DIR/allsubs.txt" -t 50
    
    if [ ! -s "$OUTPUT_DIR/allsubs.txt" ]; then
        echo -e "${RED}[-] Error: Subfinder found no subdomains. Check your targets file.${NC}"
        exit 1
    fi

    # Live host probing
    echo -e "${GREEN}[+] Running Httprobe...${NC}"
    cat "$OUTPUT_DIR/allsubs.txt" | httprobe | tee "$OUTPUT_DIR/live_https.txt"

    if [ ! -s "$OUTPUT_DIR/live_https.txt" ]; then
        echo -e "${YELLOW}[!] Warning: Httprobe found no live hosts.${NC}"
    fi

    clean_urls
    
    echo -e "\n${GREEN}[+] Subdomain collection complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[+] Statistics:${NC}"
    echo -e "  - Total subdomains found: $(wc -l < "$OUTPUT_DIR/allsubs.txt")"
    echo -e "  - Live hosts detected: $(wc -l < "$OUTPUT_DIR/live_https.txt")"
    echo -e "  - Cleaned unique domains: $(wc -l < "$OUTPUT_DIR/live_subs.txt")"
    echo -e "${GREEN}========================================${NC}"
}

# --- URL Collection Functions ---

run_optimized_command() {
    local command="$1"
    sleep "$REQUEST_DELAY"
    eval "$command" 2>/dev/null || echo ""
}

filter_urls() {
    local url
    while IFS= read -r url; do
        if [[ -z "$url" ]]; then
            continue
        fi
        
        local blocked=0
        for ext in "${BLOCKED_EXTENSIONS[@]}"; do
            if [[ "$url" == *"$ext"* ]]; then
                blocked=1
                break
            fi
        done
        
        if [[ $blocked -eq 0 ]]; then
            echo "$url"
        fi
    done
}

clean_params() {
    local url="$1"
    if [[ "$url" != *"?"* ]]; then
        echo "$url"
        return
    fi
    
    local base="${url%%\?*}"
    local query="${url#*\?}"
    
    declare -A params
    IFS='&' read -ra pairs <<< "$query"
    for pair in "${pairs[@]}"; do
        key="${pair%%=*}"
        params["$key"]="$PARAM_PLACEHOLDER"
    done
    
    local new_query=""
    for key in "${!params[@]}"; do
        if [[ -n "$new_query" ]]; then
            new_query+="&"
        fi
        new_query+="$key=${params[$key]}"
    done
    
    echo "${base}?${new_query}"
}

process_subbatch() {
    local subbatch=("$@")
    local tempfile=$(mktemp)
    printf '%s\n' "${subbatch[@]}" > "$tempfile"
    
    local pids=()
    local tool_outputs=()
    
    for tool in "${TOOLS[@]}"; do
        case "$tool" in
            "gau")
                gau --threads 5 --subs < "$tempfile" > "${tempfile}_gau" 2>/dev/null &
                pids+=($!)
                tool_outputs+=("${tempfile}_gau")
                ;;
            "waybackurls")
                waybackurls < "$tempfile" > "${tempfile}_wayback" 2>/dev/null &
                pids+=($!)
                tool_outputs+=("${tempfile}_wayback")
                ;;
            "katana")
                katana -jc -kf -d 3 -silent -c 5 < "$tempfile" > "${tempfile}_katana" 2>/dev/null &
                pids+=($!)
                tool_outputs+=("${tempfile}_katana")
                ;;
        esac
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    for output in "${tool_outputs[@]}"; do
        if [[ -f "$output" ]]; then
            while IFS= read -r url; do
                cleaned=$(clean_params "$url")
                if [[ -n "$cleaned" ]]; then
                    echo "$cleaned"
                fi
            done < <(filter_urls < "$output")
            rm "$output"
        fi
    done
    
    rm "$tempfile"
}

collect_urls() {
    local input_file="$OUTPUT_DIR/live_subs.txt"
    local final_output="$FINAL_OUTPUT_DIR/all_urls.txt"
    
    echo -e "${BLUE}[+] Starting URL collection from live subdomains...${NC}"
    
    if [ ! -s "$input_file" ]; then
        echo -e "${RED}[-] Error: No live subdomains found to process.${NC}"
        exit 1
    fi
    
    mapfile -t subdomains < "$input_file"
    local total_subbatches=$(( (${#subdomains[@]} + SUBBATCH_SIZE - 1) / SUBBATCH_SIZE ))
    
    echo -e "${GREEN}[+] Processing ${#subdomains[@]} subdomains in $total_subbatches batches${NC}"
    > "$final_output"
    
    for ((i=0; i<${#subdomains[@]}; i+=SUBBATCH_SIZE)); do
        local subbatch=("${subdomains[@]:i:SUBBATCH_SIZE}")
        local batch_num=$(( (i / SUBBATCH_SIZE) + 1 ))
        echo -e "${YELLOW}[+] Processing batch $batch_num/$total_subbatches${NC}"
        process_subbatch "${subbatch[@]}" >> "$final_output"
    done
    
    local url_count=$(wc -l < "$final_output" | tr -d ' ')
    echo -e "\n${GREEN}[+] URL collection complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[+] Final Statistics:${NC}"
    echo -e "  - Unique URLs collected: $url_count"
    echo -e "  - Output file: $final_output"
    echo -e "${GREEN}========================================${NC}"
}

# --- Main Execution ---

echo -e "\n${GREEN}=== Automated Recon Pipeline ===${NC}"

# Check dependencies
check_dependency "subfinder"
check_dependency "httprobe"
for tool in "${TOOLS[@]}"; do
    check_dependency "$tool"
done

# Setup environment
setup_environment

# Run the pipeline
collect_subdomains
collect_urls

echo -e "\n${GREEN}[+] Pipeline completed successfully!${NC}"