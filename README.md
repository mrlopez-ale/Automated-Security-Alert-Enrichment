# Automated-Security-Alert-Enrichment-Script
Linkedin: https://www.linkedin.com/in/mr-lopeza/

1. Purpose
This script automates the process of enriching basic security alerts containing IP addresses with valuable external context. It reads alerts (one JSON object per line) from an input file, extracts the source IP address, queries external threat intelligence and geolocation APIs (AbuseIPDB and ipinfo.io), and outputs the original alert combined with the enrichment data in JSON Lines format.

This helps security analysts quickly assess the risk associated with an IP address by providing reputation scores and location information directly within the alert data, reducing manual lookup time and improving triage efficiency.

2. Features
Reads alerts from a specified input file (expects JSON Lines format).

Parses JSON alerts and extracts the source_ip field.

Validates IP addresses and skips enrichment for private/internal IPs.

Enriches public IP addresses using:

AbuseIPDB: Checks IP reputation, abuse confidence score, usage type, ISP, etc.

ipinfo.io: Retrieves geolocation data (city, region, country), ISP/organization, etc.

Handles API keys securely via environment variables.

Includes robust error handling for:

Invalid input JSON.

Missing source_ip field.

Invalid IP address format.

API errors (timeouts, connection errors, rate limits, authentication issues).

Missing API keys/tokens.

Outputs enriched alerts in JSON Lines format to either the console (stdout) or a specified output file (append mode).

Provides status indicators within the output for each enrichment source and the overall IP status.

Adds a timestamp to each enriched alert.

3. Requirements
Python 3.6+ (due to f-strings and ipaddress module usage)

requests library (for making API calls)

4. Setup
Get the Script: Clone the repository or download the enrich_alert.py script.

Install Dependencies: Install the required requests library. It's recommended to use a virtual environment:

python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install requests
# Or, if a requirements.txt file is provided:
# pip install -r requirements.txt

Obtain API Keys:

AbuseIPDB: Sign up for a free account at https://www.abuseipdb.com/ and get an API key.

ipinfo.io: Sign up for a free account at https://ipinfo.io/ and get an API token.

Configure API Keys: Set the obtained API keys/tokens as environment variables in your terminal session before running the script:

export ABUSEIPDB_API_KEY='YourAbuseIPDBApiKeyHere'
export IPINFO_TOKEN='YourIpinfoTokenHere'

(Note: For persistent configuration, add these export lines to your shell profile file like .bashrc, .zshrc, or manage them through other secrets management methods.)

5. Input Format
The script expects the input file to contain one valid JSON object per line. Each JSON object represents a single alert. The script specifically looks for a field named source_ip to perform enrichment.

Example Input (alerts.log):

{"timestamp": "2025-04-23T10:00:01Z", "event_type": "AUTH_FAILURE", "source_ip": "198.51.100.123", "user": "admin"}
{"timestamp": "2025-04-23T10:05:30Z", "event_type": "FIREWALL_BLOCK", "source_ip": "203.0.113.5", "dest_ip": "10.0.0.5", "protocol": "TCP", "dest_port": 445}
{"timestamp": "2025-04-23T10:06:00Z", "event_type": "MALWARE_DETECTED", "hostname": "srv-db01"}

6. Enrichment Sources
AbuseIPDB: Provides IP address reputation, including an abuse confidence score (0-100), reported usage type, ISP, domain, and report counts.

ipinfo.io: Provides geolocation details (city, region, country, coordinates), ISP/organization information, and timezone.

7. Output Format
The script outputs enriched alerts in JSON Lines format (one complete JSON object per line). The original alert fields are preserved, and an enrichment object and an enrichment_timestamp are added.

Example Output (enriched_alerts.jsonl or Console):

{
  "timestamp": "2025-04-23T10:00:01Z",
  "event_type": "AUTH_FAILURE",
  "source_ip": "198.51.100.123",
  "user": "admin",
  "enrichment": {
    "ip_status": "public_enriched",
    "sources": {
      "abuseipdb": {
        "status": "success",
        "data": {
          "is_public": true,
          "abuse_confidence_score": 85,
          "country_code": "US",
          "usage_type": "Data Center/Web Hosting/Transit",
          "isp": "Example ISP Inc.",
          "domain": "example.com",
          "is_whitelisted": false,
          "total_reports": 15,
          "last_reported_at": "2025-04-22T15:30:00+00:00"
        }
      },
      "ipinfo": {
        "status": "success",
        "data": {
          "city": "Mountain View",
          "region": "California",
          "country": "US",
          "loc": "37.4056,-122.0775",
          "org": "AS15169 Google LLC",
          "postal": "94043",
          "timezone": "America/Los_Angeles"
        }
      }
    }
  },
  "enrichment_timestamp": "2025-04-23T18:15:10.123456Z"
}
{
  "timestamp": "2025-04-23T10:06:00Z",
  "event_type": "MALWARE_DETECTED",
  "hostname": "srv-db01",
  "enrichment": {
    "ip_status": "source_ip_not_found",
    "sources": {}
  },
  "enrichment_timestamp": "2025-04-23T18:15:11.789101Z"
}

Key fields in the enrichment object:

ip_status: Overall status for the IP (public_enriched, private, invalid_format, enrichment_error, enrichment_skipped_or_partial, source_ip_not_found, not_applicable).

sources: Contains results from each API source (abuseipdb, ipinfo).

status: Status for that specific API call (success, error, skipped_private, skipped_invalid_format, api_key_missing, token_missing).

data: (If status is success) Dictionary containing the extracted enrichment fields.

details: (If status is not success) String explaining the reason for error or skip.

enrichment_timestamp: ISO 8601 formatted UTC timestamp indicating when enrichment was performed.

8. Usage
Run the script from your terminal, providing the path to the input log file.

Output to Console:

# Ensure API keys are set first!
# export ABUSEIPDB_API_KEY='...'
# export IPINFO_TOKEN='...'

python enrich_alert.py /path/to/your/alerts.log

Append Output to File:

Use the -o or --output-file argument to specify an output file. The script will append enriched alerts (JSON Lines) to this file.

# Ensure API keys are set first!
# export ABUSEIPDB_API_KEY='...'
# export IPINFO_TOKEN='...'

python enrich_alert.py /path/to/your/alerts.log -o /path/to/output/enriched_alerts.jsonl

9. Error Handling
Invalid Input: Lines that are not valid JSON or where the parsed result is not a dictionary are skipped, and a warning is printed to stderr.

Missing source_ip: Enrichment is skipped for alerts missing the source_ip field. The ip_status will be source_ip_not_found.

Private/Invalid IPs: Enrichment is skipped, and the ip_status will reflect private or invalid_format.

API Errors: Errors during API calls (timeouts, connection issues, rate limits, bad keys) are caught. A warning is printed to stderr, and the specific source's status in the output JSON will indicate error with details. The overall ip_status will likely be enrichment_error.

Missing API Keys: If environment variables are not set, the script prints an informational message at the start, and the relevant API lookups are skipped. The source status will indicate api_key_missing or token_missing.

Progress messages and warnings/errors are printed to stderr, while the final enriched JSON Lines data is printed to stdout (if no output file is specified).
