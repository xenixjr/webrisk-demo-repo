import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, RefreshCw } from 'lucide-react';

const STORAGE_KEY = 'webRiskSubmissions';
const backendBaseUrl = 'YOUR_BACKEND_URL_PREFIX'; // e.g. https://backend-dot-tamw-webrisk-demo.uc.r.appspot.com

const saveSubmissionsToStorage = (submissions) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(submissions));
  } catch (error) {
    console.error('Error saving to localStorage:', error);
  }
};

const loadSubmissionsFromStorage = () => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch (error) {
    console.error('Error loading from localStorage:', error);
    return [];
  }
};

const WebRiskDemo = () => {
  // State management for both scan and submission features
  const [activeTab, setActiveTab] = useState('scan');
  const [url, setUrl] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [submissions, setSubmissions] = useState(() => loadSubmissionsFromStorage());
  const [expandedResultId, setExpandedResultId] = useState(null);

  const [submissionForm, setSubmissionForm] = useState({
    url: '',
    evidence: '',
    abuseType: '',
    platform: 'PLATFORM_UNSPECIFIED',
    regionCodes: ['US']
  });

  const hasHighRisk = (scores) => {
    return scores?.some(score => 
      ['MEDIUM', 'HIGH', 'HIGHER', 'EXTREMELY_HIGH'].includes(score.confidenceLevel)
    );
  };

  const handleQuickSubmit = (result) => {
    // Pre-fill the submission form with the scanned URL
    setSubmissionForm({
      ...submissionForm,
      url: result.url,
      // Pre-select abuse type based on the highest risk score
      abuseType: result.scores
        .find(score => ['MEDIUM', 'HIGH', 'HIGHER', 'EXTREMELY_HIGH'].includes(score.confidenceLevel))
        ?.threatType || ''
    });
  };

  const ABUSE_TYPES = {
    MALWARE: 'The URI contains malware',
    SOCIAL_ENGINEERING: 'The URI contains social engineering',
    UNWANTED_SOFTWARE: 'The URI contains unwanted software'
  };

  const clearSubmissionHistory = () => {
    if (window.confirm('Are you sure you want to clear all submission history?')) {
      setSubmissions([]);
      localStorage.removeItem(STORAGE_KEY);
    }
  };
  
  const getConfidenceLevelStyle = (level) => {
    switch (level) {
      case 'SAFE':
      case 'LOW':
        return 'bg-green-100 text-green-700';
      case 'MEDIUM':
        return 'bg-orange-100 text-orange-700';
      case 'HIGH':
      case 'HIGHER':
      case 'EXTREMELY_HIGH':
        return 'bg-red-100 text-red-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const PLATFORMS = {
    PLATFORM_UNSPECIFIED: 'Unspecified',
    ANDROID: 'Android',
    IOS: 'iOS',
    MACOS: 'macOS',
    WINDOWS: 'Windows'
  };

  const formatDateTime = (dateString) => {
    try {
      // Convert UTC to local time for display
      const date = new Date(dateString);
      return date.toLocaleString(undefined, {  // undefined uses the user's locale
        dateStyle: 'medium',
        timeStyle: 'medium',
      });
    } catch (error) {
      console.error('Error formatting date:', error);
      return dateString;
    }
  };

  const [isSubmitting, setIsSubmitting] = useState(false);

  // Handler for URL scanning functionality
  // Ensure that the API response data is being handled correctly
  const handleScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('${backendBaseUrl}/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
  
      if (!data.scores) {
        throw new Error('No scores received from API');
      }
  
      // Determine if the URL is safe based on the API response
      const isSafe = data.scores.every((score) => score.confidenceLevel === 'SAFE');
  
      // Create result object with resolved URL info if available
      const result = {
        id: Date.now(),
        url,
        status: isSafe ? 'safe' : 'threat',
        timestamp: new Date().toISOString(),
        scores: data.scores,
        resolvedUriScore: data.resolvedUriScore // Add resolved URL information
      };
  
      setResults([result, ...results]);
    } catch (error) {
      console.error('Error during scan:', error);
      setResults([
        {
          id: Date.now(),
          url,
          status: 'error',
          timestamp: new Date().toISOString(),
          details: error.message || 'Failed to scan URL',
        },
        ...results,
      ]);
    }
  
    setLoading(false);
    setUrl('');
  };

  // Handler for URL submission
  // Ensure that the submission form data is being handled correctly
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
  
    try {
      const response = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: submissionForm.url,
          evidence: submissionForm.evidence,
          abuseType: submissionForm.abuseType,
          platform: submissionForm.platform,
          regionCodes: submissionForm.regionCodes
        }),
      });
  
      const data = await response.json();
  
      if (data.operation) {
        const newSubmission = {
          id: Date.now(),
          url: submissionForm.url,
          operation: data.operation,
          timestamp: data.timestamp,
          lastUpdated: new Date().toISOString(),
          evidence: submissionForm.evidence,
          abuseType: submissionForm.abuseType,
          platform: submissionForm.platform,
          status: 'PENDING',
        };
  
        const updatedSubmissions = [newSubmission, ...submissions];
        setSubmissions(updatedSubmissions);
        saveSubmissionsToStorage(updatedSubmissions);
  
        // Reset form
        setSubmissionForm({
          url: '',
          evidence: '',
          abuseType: '',
          platform: 'PLATFORM_UNSPECIFIED',
          regionCodes: ['US']
        });
      }
    } catch (error) {
      console.error('Submission error:', error);
    }
  
    setIsSubmitting(false);
  };

  const refreshSubmissionStatus = async (operation) => {
    try {
      const operationId = operation.split('/').pop();
      const response = await fetch(`/api/submission/${operationId}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }
  
      const data = await response.json();
      
      const updatedSubmissions = submissions.map(sub =>
        sub.operation === operation
          ? {
              ...sub,
              status: data.status,
              lastUpdated: new Date().toISOString(),
              details: data.details
            }
          : sub
      );
      
      setSubmissions(updatedSubmissions);
      saveSubmissionsToStorage(updatedSubmissions);
    } catch (error) {
      console.error('Error refreshing submission status:', error);
    }
  };

  // Helper function for submission status styling
  const getSubmissionStatusStyle = (status) => {
    switch (status) {
      case 'SUCCEEDED':
        return {
          icon: <CheckCircle className="h-5 w-5 text-green-500" />,
          text: 'Added to blocklist',
          className: 'bg-green-100 text-green-700'
        };
      case 'CLOSED':
        return {
          icon: <AlertTriangle className="h-5 w-5 text-gray-500" />,
          text: 'Not added',
          className: 'bg-gray-100 text-gray-700'
        };
      default:
        return {
          icon: <Clock className="h-5 w-5 text-blue-500" />,
          text: 'Processing',
          className: 'bg-blue-100 text-blue-700'
        };
    }
  };

  // Main render function
  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <div className="bg-white rounded-lg shadow-lg">
        {/* Tab Navigation */}
        <div className="border-b">
          <div className="flex gap-2 px-6 pt-4">
            <button
              onClick={() => setActiveTab('scan')}
              className={`px-4 py-2 rounded-t-lg ${
                activeTab === 'scan'
                  ? 'bg-white border-b-2 border-blue-600 text-blue-600 font-semibold'
                  : 'bg-gray-50 text-gray-600 hover:bg-gray-100'
              }`}
            >
              Scan URLs
            </button>
            <button
              onClick={() => setActiveTab('submit')}
              className={`px-4 py-2 rounded-t-lg ${
                activeTab === 'submit'
                  ? 'bg-white border-b-2 border-blue-600 text-blue-600 font-semibold'
                  : 'bg-gray-50 text-gray-600 hover:bg-gray-100'
              }`}
            >
              Submit URLs
            </button>
          </div>
        </div>

        {/* Tab Content */}
        {activeTab === 'scan' ? (
          // Scan Tab Content
          <div className="p-6">
            <div className="flex items-center gap-2 mb-6">
              <Shield className="h-6 w-6 text-blue-600" />
              <h1 className="text-2xl font-bold">Google Cloud Web Risk Demo</h1>
            </div>

            <div className="flex gap-4 mb-8">
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to scan..."
                className="flex-1 px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button 
                onClick={handleScan}
                disabled={!url || loading}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {loading ? 'Scanning...' : 'Scan URL'}
              </button>
            </div>

            <div className="space-y-4">
            {results.map((result) => (
              <div key={result.id} className="bg-gray-50 rounded-lg p-4 border">
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <div className="font-medium break-all">{result.url}</div>
                    <div className="text-sm text-gray-500">
                      Scanned at: {formatDateTime(result.timestamp)}
                    </div>
                    
                    {/* Original URL Scores */}
                    {result.scores && (
                      <>
                        <div className="text-sm font-medium text-gray-700">Original URL Evaluation:</div>
                        <div className="flex flex-wrap gap-2">
                          {result.scores.map((score, index) => (
                            <span
                              key={`${score.threatType}-${index}`}
                              className={`inline-block px-2 py-1 text-xs rounded ${getConfidenceLevelStyle(score.confidenceLevel)}`}
                            >
                              {score.threatType}: {score.confidenceLevel}
                            </span>
                          ))}
                        </div>
                      </>
                    )}
                    
                    {/* Resolved URL Section */}
                    {result.resolvedUriScore && (
                      <div className="mt-4 pt-4 border-t border-gray-200">
                        <div className="text-sm font-medium text-gray-700 mb-2">
                          Resolved URL: 
                          <span className="ml-2 font-normal break-all">
                            {result.resolvedUriScore.resolvedUri}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {result.resolvedUriScore.scores.map((score, index) => (
                            <span
                              key={`resolved-${score.threatType}-${index}`}
                              className={`inline-block px-2 py-1 text-xs rounded ${getConfidenceLevelStyle(score.confidenceLevel)}`}
                            >
                              {score.threatType}: {score.confidenceLevel}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {result.scores?.every(score => ['SAFE', 'LOW'].includes(score.confidenceLevel)) &&
                    (!result.resolvedUriScore?.scores || 
                      result.resolvedUriScore.scores.every(score => ['SAFE', 'LOW'].includes(score.confidenceLevel))) ? (
                      <CheckCircle className="h-6 w-6 text-green-500" />
                    ) : (
                      <AlertTriangle className="h-6 w-6 text-red-500" />
                    )}
                  </div>
                </div>

                  {result.scores && hasHighRisk(result.scores) && (
      <div className="mt-4 pt-4 border-t border-gray-200">
        <div className="flex justify-between items-center">
          <div className="text-sm text-red-600 font-medium flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            High risk detected! Consider submitting this URL to Web Risk.
          </div>
          <button
            onClick={() => {
              if (expandedResultId === result.id) {
                setExpandedResultId(null);
              } else {
                setExpandedResultId(result.id);
                handleQuickSubmit(result);
                setActiveTab('submit');
              }
            }}
            className="text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            {expandedResultId === result.id ? 'Cancel' : 'Submit URL'}
          </button>
        </div>

        {/* Inline submission form */}
        {expandedResultId === result.id && (
          <form 
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              handleSubmit(e);
              setExpandedResultId(null);
            }}
          >
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Evidence of Violation
              </label>
              <textarea
                value={submissionForm.evidence}
                onChange={(e) => setSubmissionForm({
                  ...submissionForm,
                  evidence: e.target.value
                })}
                className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                placeholder="Describe why this URL should be submitted..."
                rows={3}
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Platform
              </label>
              <select
                value={submissionForm.platform}
                onChange={(e) => setSubmissionForm({
                  ...submissionForm,
                  platform: e.target.value
                })}
                className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                required
              >
                {Object.entries(PLATFORMS).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {isSubmitting ? 'Submitting...' : 'Submit URL'}
              </button>
            </div>
          </form>
        )}
      </div>
    )}
    </div>
  ))}

              {results.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  No scans performed yet. Enter a URL above to begin.
                </div>
              )}
            </div>
          </div>
        ) : (
          // Submit Tab Content
          <div className="p-6">
            <div className="bg-blue-50 p-4 rounded-lg mb-6">
              <h3 className="flex items-center gap-2 font-medium text-blue-800 mb-2">
                <Shield className="h-5 w-5" />
                Submission Guidelines
              </h3>
              <div className="text-sm text-blue-700 space-y-2">
                <p>Only submit URLs that clearly violate Safe Browsing policies:</p>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Social engineering/phishing sites mimicking legitimate brands</li>
                  <li>Sites distributing known malware</li>
                </ul>
                <p className="italic">Note: Submissions may take up to 24 hours to process.</p>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  URL to Submit
                </label>
                <input
                  type="text"
                  value={submissionForm.url}
                  onChange={(e) => setSubmissionForm({
                    ...submissionForm,
                    url: e.target.value
                  })}
                  className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter suspicious URL..."
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Abuse Type
                </label>
                <select
                  value={submissionForm.abuseType}
                  onChange={(e) => setSubmissionForm({
                    ...submissionForm,
                    abuseType: e.target.value
                  })}
                  className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                  required
                >
                  <option value="">Select abuse type...</option>
                  {Object.entries(ABUSE_TYPES).map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Platform
                </label>
                <select
                  value={submissionForm.platform}
                  onChange={(e) => setSubmissionForm({
                    ...submissionForm,
                    platform: e.target.value
                  })}
                  className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                  required
                >
                  {Object.entries(PLATFORMS).map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Evidence of Violation
                </label>
                <textarea
                  value={submissionForm.evidence}
                  onChange={(e) => setSubmissionForm({
                    ...submissionForm,
                    evidence: e.target.value
                  })}
                  className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                  placeholder="Describe how this URL violates policies..."
                  rows={4}
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {isSubmitting ? 'Submitting...' : 'Submit URL'}
              </button>
            </form>

            <div className="mt-8">
              <h3 className="text-lg font-medium mb-4">Submission History</h3>
              {submissions.length > 0 && (
                <button
                  onClick={clearSubmissionHistory}
                  className="text-sm text-red-600 hover:text-red-800"
                >
                  Clear History
                </button>
              )}
              <div className="space-y-4">
              {submissions.map((submission) => {
                const status = getSubmissionStatusStyle(submission.status);
                return (
                  <div key={submission.id} className="bg-gray-50 rounded-lg p-4 border">
                    <div className="flex justify-between items-start">
                      <div className="space-y-2">
                        <div className="font-medium break-all">{submission.url}</div>
                        <div className="text-sm text-gray-500">
                          Submitted: {formatDateTime(submission.timestamp)}
                          <br />
                          Last Updated: {formatDateTime(submission.lastUpdated)}
                        </div>
                        <div className="text-sm">
                          Abuse Type: {submission.abuseType}
                          <br />
                          Platform: {PLATFORMS[submission.platform]}
                        </div>
                        <div className="text-xs text-gray-500 font-mono">
                          Operation ID: {submission.operation}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <button
                          onClick={() => refreshSubmissionStatus(submission.operation)}
                          className="text-blue-600 hover:text-blue-800 text-sm flex items-center gap-1">
                          <RefreshCw className="h-4 w-4" />
                          Refresh Status
                        </button>
                        <div className={`flex items-center gap-2 px-3 py-1 rounded-full ${status.className}`}>
                          {status.icon}
                          <span className="text-sm">{status.text}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
                {submissions.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    No submissions yet. Submit a URL above to get started.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default WebRiskDemo;
