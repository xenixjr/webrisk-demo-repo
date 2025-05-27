import os
import logging
from urllib.parse import urlencode, quote_plus
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import google.auth # For the submit_url function if you keep it
from google.auth.transport.requests import AuthorizedSession # For submit_url

# Assuming utils.py with format_url exists in the same directory
from utils import format_url

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = app.logger

# Configure CORS: Replace with your actual frontend URL placeholder or direct value.
# The value from FRONTEND_ORIGIN_URL env var will be used if set.
# Default to a restrictive placeholder if env var is not set.
FRONTEND_URL = os.getenv('FRONTEND_ORIGIN_URL', 'https://your-project-id-region-id.r.appspot.com') # Fallback
CORS(app, origins=FRONTEND_URL)

@app.route('/api/scan', methods=['POST'])
def scan_url():
    logger.debug("Received scan request from frontend")
    data = request.json
    raw_url_from_frontend = data.get('url')

    if not raw_url_from_frontend:
        logger.error("No URL provided in request body")
        return jsonify({'error': 'URL is required in the request body'}), 400

    formatted_url_for_webrisk = format_url(raw_url_from_frontend)
    logger.debug(f"Formatted URL for Web Risk check: {formatted_url_for_webrisk}")

    # Initialize response variables for debugging details
    web_risk_request_url_display = "N/A"
    web_risk_status_code = None
    web_risk_response_body = None
    error_message = None
    error_details_for_frontend = None # Specific details to show frontend on error
    http_status_to_return_to_frontend = 500 # Default

    try:
        api_key = os.getenv('WEBRISK_API_KEY')
        if not api_key:
            logger.error("Critical: Missing WEBRISK_API_KEY environment variable")
            error_message = 'Server configuration error: API key missing'
            raise Exception(error_message)

        threat_types_to_check = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

        # Prepare URL for display (key omitted)
        display_params = {
            'uri': formatted_url_for_webrisk,
            'threatTypes': threat_types_to_check
        }
        display_query_string = urlencode({k:v for k,v in display_params.items() if k != 'uri'}, doseq=True)
        display_query_string += f"&uri={quote_plus(formatted_url_for_webrisk)}"
        web_risk_request_url_display = f"https://webrisk.googleapis.com/v1/uris:search?{display_query_string}"

        # Prepare actual request parameters with API key
        actual_params_with_key = display_params.copy()
        actual_params_with_key['key'] = api_key
        actual_query_string_for_request = urlencode(actual_params_with_key, doseq=True)
        actual_search_url = f"https://webrisk.googleapis.com/v1/uris:search?{actual_query_string_for_request}"

        logger.debug(f"Calling Google Web Risk API: GET {actual_search_url}") # Actual URL with key logged server-side only

        response_from_google = requests.get(actual_search_url)
        web_risk_status_code = response_from_google.status_code

        logger.debug(f"Google Web Risk API Response Status: {web_risk_status_code}")
        logger.debug(f"Google Web Risk API Response Body: {response_from_google.text}")

        response_from_google.raise_for_status() # Raises HTTPError for 4xx/5xx responses

        web_risk_response_body = response_from_google.json() if response_from_google.text else {}

        scores = []
        found_threat_object = web_risk_response_body.get('threat')

        if found_threat_object:
            threats_identified_by_google = found_threat_object.get('threatTypes', [])
            logger.info(f"Threat found for {formatted_url_for_webrisk}: {threats_identified_by_google}")
            for t_type in threat_types_to_check:
                scores.append({
                    "threatType": t_type,
                    "confidenceLevel": "HIGH" if t_type in threats_identified_by_google else "SAFE"
                })
        else:
            logger.info(f"No threat found for {formatted_url_for_webrisk}")
            for t_type in threat_types_to_check:
                scores.append({"threatType": t_type, "confidenceLevel": "SAFE"})
        
        final_response_to_frontend = {
            "scores": scores,
            "apiRequestDetails": {
                "backendRequest": {"method": request.method, "path": request.path, "body": data},
                "googleWebRiskCall": {
                    "requestUrl": web_risk_request_url_display, # Key is omitted
                    "responseStatusCode": web_risk_status_code,
                    "responseBody": web_risk_response_body
                }
            }
        }
        logger.debug(f"Sending successful response to frontend: {final_response_to_frontend}")
        http_status_to_return_to_frontend = 200
        return jsonify(final_response_to_frontend), http_status_to_return_to_frontend

    except requests.exceptions.HTTPError as http_err:
        error_details_for_frontend = response_from_google.text if 'response_from_google' in locals() and response_from_google.text else "No details from Google API."
        error_message = f"Web Risk API request failed with status {web_risk_status_code if web_risk_status_code else 'unknown'}"
        logger.error(f"HTTP error calling Web Risk API: {str(http_err)} - Details: {error_details_for_frontend}")
        http_status_to_return_to_frontend = 502 # Bad Gateway
    except requests.exceptions.RequestException as e: # Covers network errors, timeouts etc.
        error_message = f"Could not connect to Web Risk API: {str(e)}"
        logger.error(f"Network error calling Web Risk API: {str(e)}")
        http_status_to_return_to_frontend = 504 # Gateway Timeout
    except Exception as e: # Catch-all for other unexpected errors
        error_message = "Internal server error during scan"
        logger.error(f"Unexpected error in scan_url: {str(e)}", exc_info=True)
        http_status_to_return_to_frontend = 500

    # Construct and send an error response
    error_response_to_frontend = {
        "error": error_message,
        "details": error_details_for_frontend, # This might be None or contain Google's error text
        "apiRequestDetails": {
             "backendRequest": {"method": request.method, "path": request.path, "body": data},
             "googleWebRiskCall": {
                 "requestUrl": web_risk_request_url_display,
                 "responseStatusCode": web_risk_status_code, # Might be None if request didn't happen
                 "responseBody": web_risk_response_body # Might be None
             }
         }
    }
    logger.debug(f"Sending error response to frontend: {error_response_to_frontend}")
    return jsonify(error_response_to_frontend), http_status_to_return_to_frontend

# --- Add your /api/submit and /api/submission/<operation> routes here ---
# Ensure they also have proper logging and error handling, and use environment variables
# for PROJECT_NUMBER. They will also benefit from the global CORS(app) setting.

@app.route('/api/submit', methods=['POST'])
def submit_url():
    logger.debug("Received submission request")
    # ... (Your existing submit_url logic, adapted for GOOGLE_CLOUD_PROJECT_NUMBER env var)
    # Make sure to return jsonify({...}), status_code
    return jsonify({"message": "Submit endpoint placeholder"}), 200


@app.route('/api/submission/<operation>', methods=['GET'])
def check_submission_status(operation):
    logger.debug(f"Received check submission status request for operation: {operation}")
    # ... (Your existing check_submission_status logic, adapted for GOOGLE_CLOUD_PROJECT_NUMBER env var)
    # Make sure to return jsonify({...}), status_code
    return jsonify({"message": f"Check status placeholder for {operation}"}), 200

if __name__ == '__main__':
    # This is used for local development, App Engine uses the Gunicorn entrypoint
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
