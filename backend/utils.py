def format_url(url):
    """
    Ensures URLs are properly formatted for the Web Risk API.
    
    The function handles common user input patterns and converts them
    to properly formatted URLs that the API can process.
    """
    url = url.strip()
    
    # Add https:// if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    # Remove trailing slash for consistency
    return url.rstrip('/')

def validate_submission_evidence(evidence, submission_type):
    """
    Validates that the submission evidence meets Web Risk guidelines.
    
    This helps ensure we only submit URLs that have a high likelihood
    of being accepted by the Web Risk team.
    """
    if not evidence or len(evidence.strip()) < 10:
        return False, "Evidence must be detailed enough to show clear policy violation"
    
    required_keywords = {
        'phishing': ['brand', 'impersonating', 'legitimate', 'credentials'],
        'malware': ['executable', 'malware', 'infection', 'behavior']
    }
    
    # Check if evidence contains required keywords for the submission type
    keywords = required_keywords.get(submission_type, [])
    found_keywords = sum(1 for word in keywords if word.lower() in evidence.lower())
    
    if found_keywords < 2:
        return False, f"Evidence should describe how this violates {submission_type} policies"
        
    return True, "Evidence is sufficient"