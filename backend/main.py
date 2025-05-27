from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlencode, quote_plus
from google.auth.transport.requests import AuthorizedSession
from datetime import datetime
from utils import format_url, validate_submission_evidence
import google.auth
import logging
import os  # We need this for environment variables
import requests  # This is used in the scan_url function

# --- Flask App Setup ---
app = Flask(__name__)
# Configure CORS properly - replace with your actual frontend URL
# Make sure this URL is correct and doesn't have a trailing slash if your origin doesn't
frontend_origin = os.getenv('FRONTEND_ORIGIN_URL', 'YOUR_FRONTEND_ORIGIN_URL_HERE') # Example: 'https://your-project-id.uc.r.appspot.com'
CORS(app, origins=frontend_origin) # Simplified global CORS for the allowed origin
logger = app.logger
logging.basicConfig(level=logging.DEBUG) # Keep debug logging

# --- API Routes ---
@app.route('/api/scan', methods=['POST']) # Let Flask-CORS handle OPTIONS implicitly
def scan_url():
    logger.debug("Received scan request")
    data = request.json
    raw_url = data.get('url')
    if not raw_url:
        logger.error("No URL provided in request")
        return jsonify({'error': 'URL is required'}), 400

    formatted_url = format_url(raw_url)
    logger.debug(f"Formatted URL for checking: {formatted_url}")

    # Initialize response variables
    web_risk_request_url_display = "N/A" # URL sent to Google (without key)
    web_risk_status_code = None
    web_risk_response_body = None
    error_message = None
    error_details = None
    http_status_code = 500 # Default to internal error

    try:
        api_key = os.getenv('WEBRISK_API_KEY')
        if not api_key:
            logger.error("Missing WEBRISK_API_KEY environment variable")
            error_message = 'Server configuration error: API key missing'
            # Keep http_status_code as 500
            raise Exception(error_message) # Raise exception to be caught below

        threat_types = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

        # Prepare for Web Risk API v1 uris.search
        search_params = {
            # No key here for display URL
            'uri': formatted_url,
            'threatTypes': threat_types
        }
        # Encode params safely for display URL, use quote_plus for URI
        display_query_string = urlencode({k:v for k,v in search_params.items() if k != 'uri'}, doseq=True)
        display_query_string += f"&uri={quote_plus(formatted_url)}" # Safely encode the URI itself
        web_risk_request_url_display = f"https://webrisk.googleapis.com/v1/uris:search?{display_query_string}"

        # Add API key only for the actual request query string
        search_params_with_key = search_params.copy()
        search_params_with_key['key'] = api_key
        actual_query_string = urlencode(search_params_with_key, doseq=True)
        search_url = f"https://webrisk.googleapis.com/v1/uris:search?{actual_query_string}"


        logger.debug(f"Calling Web Risk API v1: GET {search_url}") # Log the actual URL with key (server-side only)

        response = requests.get(search_url)
        web_risk_status_code = response.status_code # Capture status code

        logger.debug(f"Web Risk API Response Status: {web_risk_status_code}")
        logger.debug(f"Web Risk API Response Body: {response.text}")

        response.raise_for_status() # Raise exception for 4xx/5xx errors

        web_risk_response_body = response.json() if response.text else {} # Capture response body

        # Process the response and prepare 'scores' for frontend
        scores = []
        found_threat = web_risk_response_body.get('threat')
        if found_threat:
            found_threat_types = found_threat.get('threatTypes', [])
            logger.info(f"Threat found for {formatted_url}: {found_threat_types}")
            for t_type in threat_types:
                scores.append({
                    "threatType": t_type,
                    "confidenceLevel": "HIGH" if t_type in found_threat_types else "SAFE"
                })
        else:
            logger.info(f"No threat found for {formatted_url}")
            for t_type in threat_types:
                scores.append({"threatType": t_type, "confidenceLevel": "SAFE"})

        # Construct the final successful response for the frontend
        frontend_response = {
            "scores": scores,
            "apiRequestDetails": { # New section for debug info
                "backendRequest": { # Details of request *to* backend
                     "method": request.method,
                     "path": request.path,
                     "body": data # The JSON body received
                },
                "googleWebRiskCall": { # Details of call *from* backend to Google
                    "requestUrl": web_risk_request_url_display, # URL *without* API key
                    "responseStatusCode": web_risk_status_code,
                    "responseBody": web_risk_response_body
                }
            }
        }
        logger.debug(f"Sending successful response to frontend: {frontend_response}")
        http_status_code = 200
        return jsonify(frontend_response), http_status_code

    except requests.exceptions.HTTPError as http_err:
        error_details = response.text if 'response' in locals() else "No response body"
        error_message = f"Web Risk API request failed: {str(http_err)}"
        logger.error(f"HTTP error calling Web Risk API: {str(http_err)} - Details: {error_details}")
        http_status_code = 502 # Bad Gateway seems appropriate
    except requests.exceptions.RequestException as e:
        error_message = f"Could not connect to Web Risk API: {str(e)}"
        logger.error(f"Network error calling Web Risk API: {str(e)}")
        http_status_code = 504 # Gateway Timeout
    except Exception as e:
        error_message = f"Internal server error"
        logger.error(f"Unexpected error in scan_url: {str(e)}", exc_info=True) # Log full traceback
        http_status_code = 500

    # Construct error response for the frontend
    # Include whatever details were captured before the error
    frontend_error_response = {
        "error": error_message,
        "details": error_details,
        "apiRequestDetails": {
             "backendRequest": {
                 "method": request.method,
                 "path": request.path,
                 "body": data
             },
             "googleWebRiskCall": {
                 "requestUrl": web_risk_request_url_display,
                 "responseStatusCode": web_risk_status_code,
                 "responseBody": web_risk_response_body # Might be None if error happened before response
             }
         }
    }
    logger.debug(f"Sending error response to frontend: {frontend_error_response}")
    return jsonify(frontend_error_response), http_status_code


# --- Keep other routes (/api/submit, /api/submission) and main run block ---
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
