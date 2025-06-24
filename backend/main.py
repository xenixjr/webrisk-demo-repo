from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlencode
from google.auth.transport.requests import AuthorizedSession
from datetime import datetime
from utils import format_url, validate_submission_evidence
import google.auth
import logging
import os  # We need this for environment variables
import requests  # This is used in the scan_url function


app = Flask(__name__)
CORS(app, origins="https://tamw-webrisk-demo.uc.r.appspot.com")
# Configure logging to help us debug issues
logging.basicConfig(level=logging.DEBUG)
logger = app.logger

# --- Health Check Endpoint ---
@app.route('/_ah/health')
def health_check():
    """App Engine standard health check."""
    return 'ok', 200

# --- Warm Up Handler ---
@app.route('/_ah/warmup')
def warmup():
    """App Engine warmup handler. See https://cloud.google.com/appengine/docs/standard/python3/configuring-warmup-requests."""
    # This is where you could initialize database connections, load caches, etc.
    # For now, a simple success response is all that's needed.
    return '', 200, {}

@app.route('/api/scan', methods=['POST'])
def scan_url():
    logger.debug("Received scan request")
    data = request.json
    raw_url = data.get('url')
    if not raw_url:
        logger.error("No URL provided in request")
        return jsonify({'error': 'URL is required'}), 400

    formatted_url = format_url(raw_url) # Use your formatting function
    logger.debug(f"Formatted URL for checking: {formatted_url}")

    try:
        api_key = os.getenv('WEBRISK_API_KEY')
        if not api_key:
            logger.error("Missing WEBRISK_API_KEY environment variable")
            return jsonify({'error': 'Server configuration error: API key missing'}), 500

        threat_types = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

        # --- Use Web Risk API v1 uris.search ---
        search_params = {
            'key': api_key,
            'uri': formatted_url,
            'threatTypes': threat_types
        }
        query_string = urlencode(search_params, doseq=True) # Encode params for GET request
        search_url = f"https://webrisk.googleapis.com/v1/uris:search?{query_string}"

        logger.debug(f"Calling Web Risk API v1: GET {search_url}")

        response = requests.get(search_url) # Use GET request

        logger.debug(f"Web Risk API Response Status: {response.status_code}")
        logger.debug(f"Web Risk API Response Body: {response.text}")

        response.raise_for_status() # Raise exception for 4xx/5xx errors from Google

        # Process the response from uris.search
        response_data = response.json() if response.text else {} # Handle potentially empty response body if no threat

        # Adapt response for frontend - uris.search returns a 'threat' object if found
        scores = []
        found_threat = response_data.get('threat')

        if found_threat:
            found_threat_types = found_threat.get('threatTypes', [])
            logger.info(f"Threat found for {formatted_url}: {found_threat_types}")
            for t_type in threat_types:
                scores.append({
                    "threatType": t_type,
                    # Map found threats to HIGH confidence, others to SAFE
                    "confidenceLevel": "HIGH" if t_type in found_threat_types else "SAFE"
                })
        else:
            logger.info(f"No threat found for {formatted_url}")
            # No threat found, all are SAFE
            for t_type in threat_types:
                scores.append({
                    "threatType": t_type,
                    "confidenceLevel": "SAFE"
                })

        frontend_response = {"scores": scores}
        logger.debug(f"Sending response to frontend: {frontend_response}")
        return jsonify(frontend_response)

    except requests.exceptions.HTTPError as http_err:
        error_details = response.text # Try to get error details
        logger.error(f"HTTP error calling Web Risk API: {str(http_err)} - Details: {error_details}")
        return jsonify({'error': f"Web Risk API request failed: {response.status_code}", 'details': error_details}), 502 # 502 Bad Gateway
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error calling Web Risk API: {str(e)}")
        return jsonify({'error': f"Could not connect to Web Risk API: {str(e)}"}), 504 # 504 Gateway Timeout
    except Exception as e:
        logger.error(f"Unexpected error in scan_url: {str(e)}", exc_info=True) # Log full traceback for other errors
        return jsonify({'error': f"Internal server error"}), 500


@app.route('/api/submit', methods=['POST'])
def submit_url():
    logger.debug("Received submission request")
    try:
        data = request.json
        url = data.get('url')
        evidence = data.get('evidence')
        abuse_type = data.get('abuseType')
        platform = data.get('platform', 'PLATFORM_UNSPECIFIED')
        region_codes = data.get('regionCodes', ['US'])

        if not all([url, evidence, abuse_type]):
            logger.error("Missing required fields in submission request")
            return jsonify({'error': 'Missing required fields'}), 400

        formatted_url = format_url(url)
        logger.debug(f"Formatted URL for submission: {formatted_url}")
        
        project_number = os.getenv('GOOGLE_CLOUD_PROJECT_NUMBER')
        if not project_number:
            logger.error("Missing GOOGLE_CLOUD_PROJECT_NUMBER environment variable")
            return jsonify({'error': 'Project configuration missing'}), 500

        credentials, _ = google.auth.default(
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        authed_session = AuthorizedSession(credentials)
        logger.debug("Successfully obtained Google Cloud credentials")

        submission_request = {
            "submission": {
                "uri": formatted_url
            },
            "threatInfo": {
                "abuseType": abuse_type,
                "threatConfidence": {
                    "level": "HIGH"
                },
                "threatJustification": {
                    "labels": ["MANUAL_VERIFICATION"],
                    "comments": [evidence]
                }
            },
            "threatDiscovery": {
                "platform": platform,
                "regionCodes": region_codes
            }
        }
        
        logger.debug(f"Request body: {submission_request}")
        
        response = authed_session.post(
            f"https://webrisk.googleapis.com/v1/projects/{project_number}/uris:submit",
            json=submission_request,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
        
        logger.debug(f"Submission API response status: {response.status_code}")
        logger.debug(f"Response body: {response.text}")
        
        response.raise_for_status()
        submission_data = response.json()
        
        return jsonify({
        'operation': submission_data.get('name'),
        'status': 'submitted',
        'timestamp': datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',  # Adding Z to indicate UTC
        'message': 'URL submitted successfully for review'
        })
        
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during submission: {str(http_err)}")
        return jsonify({'error': f"API request failed: {str(http_err)}"}), response.status_code
    except Exception as e:
        logger.error(f"Unexpected error during submission: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submission/<path:operation>', methods=['GET'])
def check_submission_status(operation):
    """
    Checks the status of a URL submission using the full operation path.
    """
    try:
        # Use the actual project number instead of project ID
        project_number = os.getenv('GOOGLE_CLOUD_PROJECT_NUMBER')  # Add this environment variable
        if not project_number:
            logger.error("Missing GOOGLE_CLOUD_PROJECT_NUMBER environment variable")
            return jsonify({'error': 'Project configuration missing'}), 500

        credentials, _ = google.auth.default(
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        
        # Use project number in the URL
        operations_url = f"https://webrisk.googleapis.com/v1/projects/{project_number}/operations/{operation}"
        logger.debug(f"Making request to: {operations_url}")
        
        authed_session = AuthorizedSession(credentials)
        response = authed_session.get(operations_url)
        logger.debug(f"Response status: {response.status_code}")
        logger.debug(f"Response body: {response.text}")
        
        response.raise_for_status()
        
        operation_data = response.json()
        logger.debug(f"Operation response: {operation_data}")
        
        # Extract state from metadata if present
        status = 'PENDING'
        if operation_data.get('done'):
            metadata = operation_data.get('metadata', {})
            if isinstance(metadata, dict):
                status = metadata.get('state', 'SUCCEEDED' if operation_data.get('done') else 'PENDING')
        
        return jsonify({
            'operation': operation_data.get('name'),
            'status': status,
            'details': operation_data
        })
        
    except Exception as e:
        logger.error(f"Error checking submission status: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
