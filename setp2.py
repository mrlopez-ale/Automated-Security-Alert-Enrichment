import argparse
import json
import sys
import os # Import os module for file existence check

def parse_log_line(line):
    """
    Parses a single line of JSON text into a Python dictionary.

    Args:
        line (str): A string containing a JSON object.

    Returns:
        dict: A dictionary representing the parsed JSON object, or None if parsing fails.
    """
    try:
        # Strip leading/trailing whitespace before parsing
        alert_data = json.loads(line.strip())
        # Basic validation: check if it's a dictionary
        if not isinstance(alert_data, dict):
            print(f"Warning: Parsed data is not a dictionary: {line.strip()}", file=sys.stderr)
            return None
        return alert_data
    except json.JSONDecodeError:
        print(f"Warning: Skipping invalid JSON line: {line.strip()}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Warning: Unexpected error parsing line: {e} - Line: {line.strip()}", file=sys.stderr)
        return None

def process_log_file(filepath):
    """
    Reads a log file line by line, parses each line as JSON,
    and processes the resulting alert data.

    Args:
        filepath (str): The path to the log file.
    """
    print(f"Starting processing for file: {filepath}")

    # Check if the file exists before trying to open it
    if not os.path.exists(filepath):
        print(f"Error: Log file not found at {filepath}", file=sys.stderr)
        sys.exit(1) # Exit with an error code

    processed_count = 0
    skipped_count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                # Skip empty lines
                if not line.strip():
                    continue

                alert = parse_log_line(line)
                if alert:
                    # --- Placeholder for future enrichment ---
                    # For now, just print the parsed alert
                    print(f"--- Processed Alert {i+1} ---")
                    print(json.dumps(alert, indent=2)) # Pretty print the JSON

                    # Example: Extracting the source_ip (we'll use this later)
                    source_ip = alert.get('source_ip')
                    if source_ip:
                        print(f"Extracted source_ip: {source_ip}")
                    else:
                        print("Warning: 'source_ip' field not found in this alert.")
                    print("-" * 25)
                    # --- End Placeholder ---
                    processed_count += 1
                else:
                    skipped_count += 1

    except FileNotFoundError:
        # This check is redundant due to os.path.exists, but good practice
        print(f"Error: Could not open file {filepath}. File not found.", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error: Could not read file {filepath}. IO Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nProcessing Complete.")
    print(f"Successfully processed alerts: {processed_count}")
    print(f"Skipped invalid lines: {skipped_count}")


if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Read and parse security alerts from a JSON-lines log file.")
    parser.add_argument("logfile", help="Path to the log file containing JSON alerts (one per line).")

    # Parse arguments
    args = parser.parse_args()

    # Process the log file
    process_log_file(args.logfile)
