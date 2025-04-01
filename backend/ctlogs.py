import requests
import json
import re

def search_ct_logs_for_brand(brand_name, logs=['https://ct.googleapis.com/aviator/ct/v1/get-entries']):
    """
    Scans Certificate Transparency logs for domain names potentially targeting a brand.

    Args:
        brand_name (str): The brand name to search for (e.g., "examplecorp").
        logs (list, optional): A list of CT log URLs to query.
                               Defaults to Google's Aviator log. You can find more logs at
                               https://www.certificate-transparency.org/known-logs

    Returns:
        list: A list of dictionaries, each containing information about a potentially
              malicious domain targeting the brand. Each dictionary includes:
              - 'domain': The domain name found in the CT log.
              - 'entry_index': The index of the log entry where the domain was found.
              - 'log_url': The URL of the CT log where the entry was found.
              - 'certificate': (Optional, if you want to fetch full cert details - be mindful of API limits)
                                The full certificate data from the CT log entry.
              (Currently only returns domain, index and log_url for brevity and to avoid
               overly complex initial code. Can be expanded to include full cert data.)

        Returns an empty list if no potential threats are found.
    """

    potential_threats = []
    brand_name_lower = brand_name.lower() # Case-insensitive search

    for log_url in logs:
        print(f"Scanning CT Log: {log_url}")
        start_index = 0
        batch_size = 1000 # Adjust batch size as needed, be mindful of API limits

        while True:
            url = f"{log_url}?start={start_index}&end={start_index + batch_size - 1}"
            try:
                response = requests.get(url)
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                data = response.json()

                if 'entries' not in data:
                    print(f"  No 'entries' found in response from {log_url}. Possibly end of log or API issue.")
                    break # Assume no more entries

                entries = data['entries']
                if not entries:
                    print(f"  No more entries found in this batch from {log_url}. Moving to next log or finishing.")
                    break # No more entries in this batch, likely end of log segment

                for index, entry_data in enumerate(entries):
                    entry_index = start_index + index # Actual index in the entire log

                    leaf_cert = entry_data['leaf_input']['leaf_certificate']
                    # Decode Base64 certificate
                    import base64
                    cert_bytes = base64.b64decode(leaf_cert)

                    # Basic domain extraction using regex (may need refinement)
                    common_names = re.findall(r"CN=([^,\n]+)", cert_bytes.decode('utf-8', errors='ignore'))
                    san_names = re.findall(r"DNS:([^,\n]+)", cert_bytes.decode('utf-8', errors='ignore')) # Subject Alternative Names

                    domains = set(common_names + san_names) # Use set to avoid duplicates

                    for domain in domains:
                        if brand_name_lower in domain.lower():
                            potential_threats.append({
                                'domain': domain,
                                'entry_index': entry_index,
                                'log_url': log_url,
                                # 'certificate': entry_data # Optionally include full cert data - be careful with volume
                            })
                            print(f"  Potential threat found in {log_url} at index {entry_index}: Domain '{domain}'")

                start_index += batch_size

            except requests.exceptions.RequestException as e:
                print(f"  Error fetching from {log_url}: {e}")
                break # Stop scanning this log if there's a persistent error (rate limiting, etc.)
            except json.JSONDecodeError:
                print(f"  Error decoding JSON from {log_url}. Possibly invalid response format.")
                break # Stop if JSON is invalid


    if potential_threats:
        print("\nPotential Brand Targeting Domains Found:")
        for threat in potential_threats:
            print(f"  - Domain: {threat['domain']}, Log: {threat['log_url']}, Entry Index: {threat['entry_index']}")
    else:
        print("\nNo potential brand targeting domains found in the scanned logs (based on basic search).")

    return potential_threats

if __name__ == "__main__":
    your_brand_name = "Google" # Replace with your actual brand name
    logs_to_scan = [
        'https://ct.googleapis.com/aviator/ct/v1/get-entries',
        'https://ct.googleapis.com/icarus/ct/v1/get-entries',
        'https://ct.googleapis.com/rocketeer/ct/v1/get-entries',
        'https://ct.googleapis.com/oak/ct/v1/get-entries'
        # Add more CT log URLs from https://www.certificate-transparency.org/known-logs if needed
    ]

    print(f"Starting scan for brand: '{your_brand_name}' across CT logs...")
    threats_found = search_ct_logs_for_brand(your_brand_name, logs_to_scan)

    # You can further process the 'threats_found' list, e.g., save to a file,
    # perform deeper analysis, or integrate with alert systems.