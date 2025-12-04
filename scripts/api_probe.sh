#!/bin/bash
# API Endpoint Prober
# Probes common API endpoints on target domains

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target_domain> <output_dir>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Common API paths to probe
API_PATHS=(
    "/api"
    "/api/v1"
    "/api/v2"
    "/api/v3"
    "/v1"
    "/v2"
    "/graphql"
    "/graphiql"
    "/playground"
    "/api/graphql"
    "/swagger"
    "/swagger.json"
    "/swagger/ui"
    "/api-docs"
    "/openapi.json"
    "/rest"
    "/internal"
    "/admin"
    "/admin/api"
    "/api/admin"
    "/health"
    "/healthcheck"
    "/status"
    "/metrics"
    "/debug"
    "/debug/pprof"
    "/actuator"
    "/actuator/health"
    "/info"
    "/version"
    "/.well-known/openid-configuration"
    "/oauth"
    "/oauth/token"
    "/auth"
    "/login"
    "/logout"
    "/register"
    "/api/users"
    "/api/user"
    "/api/account"
    "/api/config"
    "/api/settings"
    "/robots.txt"
    "/sitemap.xml"
    "/.git/config"
    "/.env"
    "/config.json"
    "/package.json"
    "/composer.json"
    "/server-status"
    "/server-info"
    "/phpinfo.php"
    "/info.php"
    "/test"
    "/test.php"
    "/backup"
    "/dump"
    "/trace"
)

echo "[*] Probing API endpoints on: $TARGET"
echo "[*] Testing ${#API_PATHS[@]} paths..."

echo "url,status,length,redirect" > "$OUTPUT_DIR/api_probe_results.csv"

for path in "${API_PATHS[@]}"; do
    url="https://${TARGET}${path}"
    
    # Get response with curl
    response=$(curl -s -o /dev/null -w "%{http_code},%{size_download},%{redirect_url}" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        --max-time 10 \
        "$url" 2>/dev/null)
    
    status=$(echo "$response" | cut -d',' -f1)
    size=$(echo "$response" | cut -d',' -f2)
    redirect=$(echo "$response" | cut -d',' -f3)
    
    # Log interesting responses (not 403 or 404)
    if [ "$status" != "403" ] && [ "$status" != "404" ] && [ "$status" != "000" ]; then
        echo "[!] FOUND: $url -> $status (size: $size)"
        echo "$url,$status,$size,$redirect" >> "$OUTPUT_DIR/api_probe_results.csv"
    else
        echo "[ ] $url -> $status"
    fi
done

echo ""
echo "[*] Results saved to: $OUTPUT_DIR/api_probe_results.csv"

# Count interesting findings
interesting=$(grep -v "403\|404\|000\|url,status" "$OUTPUT_DIR/api_probe_results.csv" 2>/dev/null | wc -l)
echo "[*] Found $interesting potentially interesting endpoints"
