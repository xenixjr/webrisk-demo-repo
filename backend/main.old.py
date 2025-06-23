from flask_cors import CORS
from flask import Flask, request, jsonify
from google.auth.transport.requests import AuthorizedSession
import google.auth
import logging
from datetime import datetime
from utils import format_url, validate_submission_evidence
import os  # We need this for environment variables
import requests  # This is used in the scan_url function

app = Flask(__name__)

# vvv REPLACE THE OLD CORS LINE WITH THIS vvv
CORS(app, resources={r"/api/*": {"origins": "https://tamw-webrisk-demo.uc.r.appspot.com"}})
# ^^^ REPLACE THE OLD CORS LINE WITH THIS ^^^

# Configure logging to help us debug issues
logging.basicConfig(level=logging.DEBUG)
logger = app.logger

@app.route('/api/scan', methods=['POST'])
def scan_url():
    logger.debug("Received scan request")
    data = request.json
    raw_url = data.get('url')
    formatted_url = format_url(raw_url)
    
    try:
        api_key = os.getenv('WEBRISK_API_KEY')
        request_body = {
            "uri": formatted_url,
            "resolve_shortlinks": True,
            "threatTypes": [
                "SOCIAL_ENGINEERING",
                "MALWARE",
                "UNWANTED_SOFTWARE"
            ]
        }
        
        response = requests.post(
            f"https://webrisk.googleapis.com/v1:evaluateUri?key={api_key}",
            json=request_body,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
        
        logger.debug(f"API Response Status: {response.status_code}")
        logger.debug(f"API Response Body: {response.text}")
        
        response_data = response.json()
        if 'resolvedUri' in response_data:
            logger.info(f"Shortlink resolved: {raw_url} -> {response_data['resolvedUri']}")
        
        response.raise_for_status()
        return jsonify(response_data)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during API request: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/submission/<operation>', methods=['GET'])
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