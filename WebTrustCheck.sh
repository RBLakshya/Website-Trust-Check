#!/bin/bash

# Define color codes for formatting
GREEN=$(tput setaf 2)
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
MAGENTA=$(tput setaf 5)
BOLD=$(tput bold)
RESET=$(tput sgr0)

TEMP_FILE="$HOME/Desktop/LSP Project/Compiled_Run.txt"

# Test and create the temp file
touch "$TEMP_FILE"
if [[ $? -ne 0 ]]; then
    echo "Error: Unable to create file at $TEMP_FILE"
    exit 1
fi

echo "Temporary file created at: $TEMP_FILE"

print_border() {
    echo "${CYAN}${BOLD}========================================================${RESET}"
}

section_header() {
    echo ""
    print_border
    echo "${MAGENTA}${BOLD}*** $1 ***${RESET}"
    print_border
}

# WHOIS
fetch_whois() {
    section_header "Detailed Domain Information and Security Insights"

    local registrar=$(whois "$domain" | grep -i 'Registrar:' | head -n 1 | awk '{$1=""; print $0}')
    local creation_date=$(whois "$domain" | grep -i 'Creation Date:' | head -n 1 | awk '{print $NF}')
    local expiry_date=$(whois "$domain" | grep -i 'Expiry Date:' | head -n 1 | awk '{print $NF}')
    local registrant=$(whois "$domain" | grep -i 'Registrant Name:' | head -n 1 | awk '{$1=""; print $0}')
    local registrant_org=$(whois "$domain" | grep -i 'Registrant Organization:' | head -n 1 | awk '{$1=""; print $0}')
    local registrant_country=$(whois "$domain" | grep -i 'Registrant Country:' | head -n 1 | awk '{print $NF}')
    local updated_date=$(whois "$domain" | grep -i 'Updated Date:' | head -n 1 | awk '{print $NF}')

    echo "${GREEN}Registrar:${RESET} ${YELLOW}${registrar:-Not Available}${RESET}"
    echo "${GREEN}Registrant Name:${RESET} ${YELLOW}${registrant:-Not Available}${RESET}"
    echo "${GREEN}Registrant Organization:${RESET} ${YELLOW}${registrant_org:-Not Available}${RESET}"
    echo "${GREEN}Registrant Country:${RESET} ${YELLOW}${registrant_country:-Not Available}${RESET}"
    echo "${GREEN}Domain Created On:${RESET} ${YELLOW}${creation_date:-Not Available}${RESET}"
    echo "${GREEN}Last Updated On:${RESET} ${YELLOW}${updated_date:-Not Available}${RESET}"
    echo "${GREEN}Expires On:${RESET} ${YELLOW}${expiry_date:-Not Available}${RESET}"

    echo ""
    echo "${CYAN}${BOLD}Security Insights:${RESET}"

    if [[ -n "$expiry_date" && "$(date -d "$expiry_date" +%s)" -lt "$(date +%s)" ]]; then
        echo "${RED}⚠️  Domain has expired. This may indicate an inactive or abandoned site.${RESET}"
    elif [[ -n "$expiry_date" ]]; then
        local days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
        if (( days_until_expiry < 30 )); then
            echo "${RED}⚠️  Domain will expire in $days_until_expiry days. Renewal is advised.${RESET}"
        else
            echo "${GREEN}✔️  Domain is active with $days_until_expiry days until expiry.${RESET}"
        fi
    fi

    if [[ -z "$registrant" || -z "$registrant_country" ]]; then
        echo "${RED}⚠️  Registrant information is limited. This may reduce trustworthiness.${RESET}"
    elif [[ "$registrant_country" =~ ^(CN|RU|KP|IR|SY|CU)$ ]]; then
        echo "${RED}⚠️  Registrant country flagged as high-risk for security concerns.${RESET}"
    else
        echo "${GREEN}✔️  Registrant information is complete.${RESET}"
    fi
}

# SSL
fetch_ssl_info() {
    section_header "SSL Certificate Information and Security Status"

    local ssl_info=$(echo | openssl s_client -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates -issuer -subject)
    local issuer=$(echo "$ssl_info" | grep 'issuer=' | sed 's/issuer= //')
    local subject=$(echo "$ssl_info" | grep 'subject=' | sed 's/subject= //')
    local start_date=$(echo "$ssl_info" | grep 'notBefore=' | sed 's/notBefore=//')
    local expiry_date=$(echo "$ssl_info" | grep 'notAfter=' | sed 's/notAfter=//')

    echo "${GREEN}Issuer:${RESET} ${YELLOW}${issuer:-Not Available}${RESET}"
    echo "${GREEN}Subject (Owner):${RESET} ${YELLOW}${subject:-Not Available}${RESET}"
    echo "${GREEN}Valid From:${RESET} ${YELLOW}${start_date:-Not Available}${RESET}"
    echo "${GREEN}Expires On:${RESET} ${YELLOW}${expiry_date:-Not Available}${RESET}"

    echo ""
    echo "${CYAN}${BOLD}Security Insights:${RESET}"
    if [[ -n "$expiry_date" && "$(date -d "$expiry_date" +%s)" -lt "$(date +%s)" ]]; then
        echo "${RED}⚠️  SSL certificate has expired.${RESET}"
    elif [[ -n "$expiry_date" ]]; then
        local days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
        if (( days_until_expiry < 30 )); then
            echo "${RED}⚠️  SSL certificate will expire in $days_until_expiry days.${RESET}"
        else
            echo "${GREEN}✔️  SSL certificate is valid for $days_until_expiry days.${RESET}"
        fi
    else
        echo "${RED}⚠️  No valid SSL certificate found.${RESET}"
    fi
}

# IP
fetch_ip_info() {
    section_header "IP and Geolocation"
    ip=$(dig +short "$domain")
    if [ -n "$ip" ]; then
        echo "${GREEN}${BOLD}IP Address:${RESET} $ip"
        curl -s "https://ipinfo.io/$ip" | grep -E '"city"|"region"|"country"|"org"' \
            | awk -v color="$YELLOW" -F\" '{print color $4}'
    else
        echo "${RED}Could not retrieve IP address.${RESET}"
    fi
}
# DNS
fetch_dns_records() {
    section_header "DNS Records and Security Configuration"

    # Fetch and display DNS records
    echo "${GREEN}A Record:${RESET}"
    local a_record=$(dig "$domain" A +short)
    echo "${YELLOW}${a_record:-Not Available}${RESET}"

    echo "${GREEN}MX Record:${RESET}"
    local mx_record=$(dig "$domain" MX +short)
    echo "${YELLOW}${mx_record:-Not Available}${RESET}"

    echo "${GREEN}TXT Record:${RESET}"
    local txt_record=$(dig "$domain" TXT +short)
    echo "${YELLOW}${txt_record:-Not Available}${RESET}"

    # Security insights on DNS configuration
    echo ""
    echo "${CYAN}${BOLD}Security Insights:${RESET}"
    if [ -z "$mx_record" ]; then
        echo "${RED}⚠️  No MX records found. The domain might not support email or could be suspicious.${RESET}"
    else
        echo "${GREEN}✔️  MX records found. Domain appears to support email communication.${RESET}"
    fi

    if [[ "$txt_record" =~ "spf" ]]; then
        echo "${GREEN}✔️  SPF record found in TXT records, indicating some level of email security.${RESET}"
    else
        echo "${RED}⚠️  No SPF record found. The domain may be vulnerable to email spoofing.${RESET}"
    fi
}

fetch_security_headers() {
    section_header "HTTP Security Headers and Protection Status"

    # Fetch security headers
    local headers=$(curl -sI "$domain" | grep -E 'Server|Content-Security-Policy|X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security')
    echo "${YELLOW}${headers}${RESET}"

    # Security insights on headers
    echo ""
    echo "${CYAN}${BOLD}Security Insights:${RESET}"
    if [[ "$headers" != *"Strict-Transport-Security"* ]]; then
        echo "${RED}⚠️  Missing Strict-Transport-Security header. HTTPS connections may not be fully enforced.${RESET}"
    else
        echo "${GREEN}✔️  Strict-Transport-Security is present. HTTPS connections are enforced.${RESET}"
    fi

    if [[ "$headers" != *"Content-Security-Policy"* ]]; then
        echo "${RED}⚠️  Missing Content-Security-Policy header. The site may be vulnerable to XSS attacks.${RESET}"
    else
        echo "${GREEN}✔️  Content-Security-Policy header is present. XSS protection is likely enabled.${RESET}"
    fi
}

#Google safe browsing
fetch_safe_browsing_status() {
    section_header "Google Safe Browsing Status"

    # Perform the Safe Browsing API check
    local safe_browsing_api="https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY"
    local response=$(curl -s -X POST -H "Content-Type: application/json" -d "{
      'client': { 'clientId': 'web_security_tool', 'clientVersion': '1.0' },
      'threatInfo': { 'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
      'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'],
      'threatEntries': [{'url': 'http://$domain'}] }}" "$safe_browsing_api")

    # Security insights based on Google Safe Browsing
    if echo "$response" | grep -q 'matches'; then
        echo "${RED}${BOLD}Warning:${RESET} ${RED}The site is flagged by Google Safe Browsing for potential security threats.${RESET}"
    else
        echo "${GREEN}✔️  The site appears safe according to Google Safe Browsing.${RESET}"
    fi
}

fetch_trust_score() {
    section_header "Trust Score (VirusTotal Analysis)"

    # Fetch VirusTotal report using API
    local virustotal_api="https://www.virustotal.com/vtapi/v2/domain/report"
    local response=$(curl -s -G --data-urlencode "apikey=YOUR_API_KEY" --data-urlencode "domain=$domain" "$virustotal_api")

    # Check for suspicious indicators
    local positives=$(echo "$response" | grep -oP '(?<="detected_urls":\s*\[.*?\],\s*"detected_downloaded_samples":\s*\[.*?\],\s*"detected_communicating_samples":\s*\[.*?\],\s*"detected_referrer_samples":\s*\[.*?\])' | wc -l)

    echo "${GREEN}VirusTotal Analysis:${RESET}"
    echo "${GREEN}Number of detections:${RESET} ${YELLOW}${positives}${RESET}"

    # Security insights based on VirusTotal results
    echo ""
    echo "${CYAN}${BOLD}Security Insights:${RESET}"
    if (( positives > 0 )); then
        echo "${RED}⚠️  VirusTotal has flagged this site with potential threats. Proceed with caution.${RESET}"
    else
        echo "${GREEN}✔️  VirusTotal has found no significant security issues with this site.${RESET}"
    fi
}

run_all_checks() {
    local temp_file=$(mktemp)
    echo "${CYAN}${BOLD}Running all checks...${RESET}"
    echo "${CYAN}Results will be compiled into a final summary.${RESET}"

    # Run each function and append output to the temp file
    {
        fetch_whois
        fetch_ssl_info
        fetch_ip_info
        fetch_dns_records
        fetch_security_headers
        fetch_safe_browsing_status
        fetch_trust_score
    } >>"$temp_file"

    # Display individual outputs
    cat "$temp_file"

    # Summarize results
    echo ""
    echo "${MAGENTA}${BOLD}Final Summary:${RESET}"
    echo "${GREEN}${BOLD}Overall Domain Status:${RESET}"

    # Check for security insights in the file
    if grep -q "⚠️" "$temp_file"; then
        echo "${RED}Potential issues were found during the analysis. Please review the detailed results.${RESET}"
    else
        echo "${GREEN}All checks passed without significant issues.${RESET}"
    fi

    echo ""
    echo "${YELLOW}Detailed results are stored in: Compiled_Run.txt{RESET}"
    echo "You can review or delete the file manually."

    # Append temp file content to the desired file
    cat /tmp/tmp.q1IeZb33BE >> Compiled_Run.txt

    # Clean up temp file
    rm /tmp/tmp.q1IeZb33BE

}

display_menu() {
    echo "${CYAN}Select an option to analyze $domain:${RESET}"
    echo "1) WHOIS Information"
    echo "2) SSL Certificate Information"
    echo "3) IP Address and Geolocation"
    echo "4) DNS Records"
    echo "5) HTTP Security Headers"
    echo "6) Google Safe Browsing Status"
    echo "7) Trust Score (VirusTol)"
    #echo "8) Password Security Checker"
    echo "8) Run All Checks"
    #echo "8) Subdomain Scanner"
    echo "9) Exit"
    read -p "Enter your choice: " choice
}

read -p "Enter website URL (without http/https): " domain
while true; do
    display_menu
    case $choice in
        1) fetch_whois ;;
        2) fetch_ssl_info ;;
        3) fetch_ip_info ;;
        4) fetch_dns_records ;;
        5) fetch_security_headers ;;
        6) fetch_safe_browsing_status ;;
        7) fetch_trust_score ;;
        8) run_all_checks ;;  # Updated Run All option
        9) exit 0 ;;
        *) echo "${RED}Invalid choice. Please try again.${RESET}" ;;
    esac
    echo ""
done
