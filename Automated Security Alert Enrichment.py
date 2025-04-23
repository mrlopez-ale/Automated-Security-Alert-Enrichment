# Automated Security Alert Enrichment

import argparse
import json
import sys
import os
import requests # Library for making HTTP requests
import ipaddress # Library to check for private/public IPs
from datetime import datetime # For timestamping enrichment

# --- Configuration ---
# Load API keys securely from environment variables
# It's crucial these are set in the environment where the script runs
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')

# --- API Enrichment Functions ---

def get_ip_reputation(ip_address, api_key):
    """
    Queries the AbuseIPDB API for IP reputation information.

    Handles IP validation (private/invalid format) and API communication errors.

    Args:
        ip_address (str): The IP address to check.
        api_key (str): The AbuseIPDB API key.

    Returns:
        dict: Contains 'status' ('success', 'error', 'skipped_private', etc.)
              and 'data' (on success) or 'details' (on error/skip).
    """
    # Check if API key is configured
    if not api_key:
        return {"status": "api_key_missing", "details": "AbuseIPDB API key not configured."}

    # Validate IP address format and check if it's private
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return {"status": "skipped_private", "details": "IP is private."}
    except ValueError:
        # Handle cases where the input string is not a valid IP address
        return {"status": "skipped_invalid_format", "details": "Invalid IP address format."}

    # Define API endpoint and parameters
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'} # Check reports within the last 90 days

    # Make the API call with error handling
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10) # 10-second timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx client error, 5xx server error)

        # Check if the response content type is JSON before parsing
        if 'application/json' in response.headers.get('Content-Type', ''):
            api_data = response.json().get('data', {})
            # Extract specific fields into a cleaner structure for our output
            extracted_data = {
                "is_public": api_data.get("isPublic"),
                "abuse_confidence_score": api_data.get("abuseConfidenceScore"),
                "country_code": api_data.get("countryCode"),
                "usage_type": api_data.get("usageType"),
                "isp": api_data.get("isp"),
                "domain": api_data.get("domain"),
                "is_whitelisted": api_data.get("isWhitelisted"),
                "total_reports": api_data.get("totalReports"),
                "last_reported_at": api_data.get("lastReportedAt"),
            }
            # Return success status and the extracted data
            return {"status": "success", "data": extracted_data}
        else:
            # Handle cases where the API returns success status but not JSON content
            details = f"Non-JSON response, status {response.status_code}"
            print(f"Warning: AbuseIPDB returned: {details} for {ip_address}", file=sys.stderr)
            return {"status": "error", "details": details}

    # Handle specific request exceptions
    except requests.exceptions.Timeout:
        details = "Request timed out"
        print(f"Warning: Timeout connecting to AbuseIPDB for IP {ip_address}", file=sys.stderr)
        return {"status": "error", "details": details}
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else 'Unknown'
        details = f"HTTP Error {status_code}"
        # Provide more specific feedback for common HTTP errors
        if status_code == 401 or status_code == 403: details += " (Authentication/Permission Error - Check API Key)"
        elif status_code == 429: details += " (Rate Limit Exceeded)"
        elif status_code == 400: details += " (Bad Request - Check Parameters)"
        elif status_code >= 500: details += " (Server Error)"
        print(f"Warning: {details} connecting to AbuseIPDB for IP {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}
    except requests.exceptions.RequestException as e:
        # Catch other connection-related errors (DNS, network unreachable)
        details = f"Connection error: {e}"
        print(f"Warning: Connection Error connecting to AbuseIPDB for IP {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}
    except Exception as e:
        # Catch any other unexpected errors during the process
        details = f"Unexpected error: {e}"
        print(f"Warning: Unexpected error during AbuseIPDB lookup for {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}


def get_geolocation(ip_address, token):
    """
    Queries the ipinfo.io API for IP geolocation information.

    Handles IP validation (private/invalid format) and API communication errors.

    Args:
        ip_address (str): The IP address to check.
        token (str): The ipinfo.io API token.

    Returns:
        dict: Contains 'status' ('success', 'error', 'skipped_private', etc.)
              and 'data' (on success) or 'details' (on error/skip).
    """
    # Check if API token is configured
    if not token:
        return {"status": "token_missing", "details": "ipinfo.io token not configured."}

    # Validate IP address format and check if it's private
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return {"status": "skipped_private", "details": "IP is private."}
    except ValueError:
        return {"status": "skipped_invalid_format", "details": "Invalid IP address format."}

    # Define API endpoint and headers (using Bearer token authentication)
    url = f'https://ipinfo.io/{ip_address}/json'
    headers = {'Accept': 'application/json', 'Authorization': f'Bearer {token}'}

    # Make the API call with error handling
    try:
        response = requests.get(url, headers=headers, timeout=10) # 10-second timeout
        response.raise_for_status() # Raise HTTPError for bad responses

        # Check if the response content type is JSON before parsing
        if 'application/json' in response.headers.get('Content-Type', ''):
             api_data = response.json()
             # Extract specific fields into a cleaner structure
             extracted_data = {
                "hostname": api_data.get("hostname"), # Often available on ipinfo
                "city": api_data.get("city"),
                "region": api_data.get("region"),
                "country": api_data.get("country"),
                "loc": api_data.get("loc"), # Latitude/Longitude string
                "org": api_data.get("org"), # ISP / Organization
                "postal": api_data.get("postal"),
                "timezone": api_data.get("timezone")
             }
             # Return success status and the extracted data
             return {"status": "success", "data": extracted_data}
        else:
            # Handle cases where the API returns success status but not JSON content
            details = f"Non-JSON response, status {response.status_code}"
            print(f"Warning: ipinfo.io returned: {details} for {ip_address}", file=sys.stderr)
            return {"status": "error", "details": details}

    # Handle specific request exceptions
    except requests.exceptions.Timeout:
        details = "Request timed out"
        print(f"Warning: Timeout connecting to ipinfo.io for IP {ip_address}", file=sys.stderr)
        return {"status": "error", "details": details}
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else 'Unknown'
        details = f"HTTP Error {status_code}"
        # Provide more specific feedback for common HTTP errors
        if status_code == 401 or status_code == 403: details += " (Authentication/Permission Error - Check API Token)"
        elif status_code == 429: details += " (Rate Limit Exceeded)"
        elif status_code == 400: details += " (Bad Request)"
        elif status_code >= 500: details += " (Server Error)"
        print(f"Warning: {details} connecting to ipinfo.io for IP {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}
    except requests.exceptions.RequestException as e:
        details = f"Connection error: {e}"
        print(f"Warning: Error connecting to ipinfo.io for IP {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}
    except Exception as e:
        details = f"Unexpected error: {e}"
        print(f"Warning: Unexpected error during ipinfo.io lookup for {ip_address}: {e}", file=sys.stderr)
        return {"status": "error", "details": details}


# --- Core Logic ---

def parse_log_line(line_number, line_content):
    """
    Parses a single line of potentially JSON text into a Python dictionary.

    Args:
        line_number (int): The line number in the file (for error reporting).
        line_content (str): The raw string content of the line.

    Returns:
        dict: A dictionary representing the parsed JSON object, or None if
              the line is empty, invalid JSON, or not a dictionary object.
    """
    # Remove leading/trailing whitespace
    clean_line = line_content.strip()
    # Silently ignore empty lines
    if not clean_line:
        return None
    # Attempt to parse the JSON
    try:
        alert_data = json.loads(clean_line)
        # Ensure the parsed result is a dictionary (not just a string, number, etc.)
        if not isinstance(alert_data, dict):
            print(f"Warning (Line {line_number}): Parsed data is not a dictionary object: {clean_line}", file=sys.stderr)
            return None
        return alert_data
    except json.JSONDecodeError:
        # Handle lines that are not valid JSON
        print(f"Warning (Line {line_number}): Skipping invalid JSON: {clean_line}", file=sys.stderr)
        return None
    except Exception as e:
        # Catch any other unexpected errors during parsing
        print(f"Warning (Line {line_number}): Unexpected error parsing line: {e} - Line: {clean_line}", file=sys.stderr)
        return None

def process_log_file(filepath, output_file=None):
    """
    Reads alerts from the input file, enriches them, and writes to output.

    Args:
        filepath (str): The path to the input log file (JSON Lines format).
        output_file (str, optional): Path to the output file. If None, output
                                     is printed to standard output (console).
                                     Defaults to None.
    """
    print(f"Starting processing for input file: {filepath}", file=sys.stderr)
    if output_file:
        print(f"Output will be appended to: {output_file}", file=sys.stderr)
    else:
        print("Output will be printed to console (stdout).", file=sys.stderr)

    # Check for API keys at the start and inform the user via stderr
    if not ABUSEIPDB_API_KEY:
        print("Info: ABUSEIPDB_API_KEY environment variable not set. IP reputation checks may be skipped or fail.", file=sys.stderr)
    if not IPINFO_TOKEN:
        print("Info: IPINFO_TOKEN environment variable not set. Geolocation checks may be skipped or fail.", file=sys.stderr)

    # Ensure the input file exists before proceeding
    if not os.path.exists(filepath):
        print(f"Error: Input log file not found at {filepath}", file=sys.stderr)
        sys.exit(1) # Exit script with an error code

    processed_count = 0
    skipped_count = 0
    output_handle = None

    try:
        # --- Setup Output Destination ---
        if output_file:
            # Open the output file in append mode ('a') with UTF-8 encoding
            # This creates the file if it doesn't exist, appends if it does
            output_handle = open(output_file, 'a', encoding='utf-8')
        else:
            # Use standard output if no file is specified
            output_handle = sys.stdout

        # --- Process Input File ---
        # Open the input file safely using 'with' for automatic closing
        with open(filepath, 'r', encoding='utf-8') as f_input:
            # Read file line by line, getting line number for logging
            for i, line in enumerate(f_input, 1):
                # Parse the current line
                alert = parse_log_line(i, line)

                # Proceed only if parsing was successful (alert is a dictionary)
                if alert:
                    # Extract the source IP address using .get() for safety
                    source_ip = alert.get('source_ip')
                    enrichment_results = {} # Dictionary to hold results from all sources
                    ip_status = "not_applicable" # Default status if no IP field

                    # --- Enrichment Section ---
                    if source_ip:
                        # Log enrichment attempt to stderr (to avoid mixing with JSON output on stdout)
                        # Only log periodically or if verbose flag is set to reduce noise
                        if processed_count % 100 == 0 and not output_file: # Example: log every 100 to console
                             print(f"Info (Line {i}): Attempting enrichment for IP: {source_ip}...", file=sys.stderr)

                        # Call enrichment functions (these handle internal errors/skips)
                        reputation_result = get_ip_reputation(source_ip, ABUSEIPDB_API_KEY)
                        geolocation_result = get_geolocation(source_ip, IPINFO_TOKEN)

                        # Store results from each source
                        enrichment_results['abuseipdb'] = reputation_result
                        enrichment_results['ipinfo'] = geolocation_result

                        # Determine overall IP status based on individual results
                        # Prioritize specific skip reasons over general errors or success
                        if reputation_result['status'] == 'skipped_invalid_format' or \
                           geolocation_result['status'] == 'skipped_invalid_format':
                            ip_status = 'invalid_format'
                        elif reputation_result['status'] == 'skipped_private' or \
                             geolocation_result['status'] == 'skipped_private':
                            ip_status = 'private'
                        elif reputation_result['status'] == 'error' or \
                             geolocation_result['status'] == 'error':
                            ip_status = 'enrichment_error'
                        elif reputation_result['status'] == 'success' or \
                             geolocation_result['status'] == 'success':
                             # Mark as enriched if at least one source succeeded
                             ip_status = 'public_enriched'
                        else:
                             # Covers cases like only missing keys but valid IP
                             ip_status = 'enrichment_skipped_or_partial'
                    else:
                        # Handle alerts where the 'source_ip' field is missing
                        ip_status = 'source_ip_not_found'
                        if not output_file: # Log warning only when outputting to console
                            print(f"Warning (Line {i}): 'source_ip' field not found. Skipping enrichment.", file=sys.stderr)

                    # Add the structured enrichment data to the original alert
                    alert['enrichment'] = {
                        "ip_status": ip_status,
                        "sources": enrichment_results # Keep results nested under sources
                    }
                    # Add a timestamp (UTC) indicating when enrichment was performed
                    alert['enrichment_timestamp'] = datetime.utcnow().isoformat() + 'Z'

                    # --- Output Section ---
                    try:
                        # Write the complete enriched alert as a single JSON line
                        # Use separators=(',', ':') for compact output without extra spaces
                        output_handle.write(json.dumps(alert, separators=(',', ':')) + '\n')
                        # Ensure the output buffer is flushed, especially for stdout
                        output_handle.flush()
                    except TypeError as e:
                         # Handle rare errors serializing the final alert object
                         print(f"Error (Line {i}): Could not serialize enriched alert to JSON: {e}", file=sys.stderr)
                         print(f"Problematic alert data structure: {alert}", file=sys.stderr)
                         skipped_count += 1 # Count as skipped if cannot serialize
                         continue # Skip writing this alert

                    processed_count += 1
                    # Print progress to stderr periodically
                    if processed_count % 500 == 0: # Adjust frequency as needed
                         print(f"Processed {processed_count} alerts...", file=sys.stderr)

                else: # parse_log_line returned None (empty line or invalid JSON)
                    skipped_count += 1
                    # Warnings/errors for parsing are handled within parse_log_line

    # Handle potential file errors during opening/reading/writing
    except FileNotFoundError:
        print(f"Error: Could not open input file {filepath}. File not found.", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        # Covers issues reading input or writing output
        print(f"Error: File I/O error. Could not read '{filepath}' or write to output destination. Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors during the main processing loop
        print(f"An unexpected error occurred during file processing: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # --- Cleanup ---
        # Ensure the output file handle is closed if it was opened
        if output_handle and output_file:
            try:
                output_handle.close()
                print(f"Output file '{output_file}' closed.", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Error closing output file '{output_file}': {e}", file=sys.stderr)

    # --- Final Summary ---
    # Print summary statistics to stderr
    print(f"\nProcessing Complete.", file=sys.stderr)
    print(f"Successfully processed and output alerts: {processed_count}", file=sys.stderr)
    print(f"Skipped lines (empty/invalid JSON/serialization error): {skipped_count}", file=sys.stderr)


# --- Main execution block ---
if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Read security alerts (JSON lines) from a file, enrich source IPs using external APIs, and output enriched alerts.",
        formatter_class=argparse.RawTextHelpFormatter, # Preserve formatting in epilog help text
        epilog="""Requires the 'requests' library: pip install requests
Set environment variables for API keys/tokens before running:
  export ABUSEIPDB_API_KEY='YourAbuseIPDBApiKey'
  export IPINFO_TOKEN='YourIpinfoToken'

Example Usage:
  # Read from input.log and print enriched JSON lines to console
  python enrich_alert.py /var/log/custom_alerts.log

  # Read from input.log and append enriched JSON lines to output.jsonl
  python enrich_alert.py input.log -o output.jsonl
  python enrich_alert.py input.log --output-file /path/to/enriched.log
"""
    )
    # Define mandatory positional argument for the input log file
    parser.add_argument(
        "logfile",
        help="Path to the input log file containing JSON alerts (one per line)."
    )
    # Define optional argument for the output file
    parser.add_argument(
        "-o", "--output-file",
        metavar="FILE", # Use 'FILE' in help message instead of the argument name
        help="Optional path to an output file. Enriched alerts (JSON lines) will be appended. If omitted, output goes to stdout.",
        default=None # Default is None, meaning print to console (stdout)
    )

    # Parse the command-line arguments provided by the user
    args = parser.parse_args()

    # --- Dependency Check ---
    # Optional: Check if required libraries are installed before proceeding
    try:
        import requests
        import ipaddress
    except ImportError as import_error:
        print(f"Error: Missing required library. Please install it. ({import_error})", file=sys.stderr)
        print("Try running: pip install requests", file=sys.stderr)
        sys.exit(1) # Exit if dependencies are missing

    # --- Execute Main Logic ---
    # Call the main processing function with the parsed arguments
    process_log_file(args.logfile, args.output_file)
