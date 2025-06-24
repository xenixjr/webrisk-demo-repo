import React, { useState } from 'react';
import { Shield, AlertTriangle, Clock, CheckCircle } from 'lucide-react';

// This component provides guidelines to users about what URLs are appropriate to submit
const SubmissionGuidelines = () => (
  <div className="bg-blue-50 p-4 rounded-lg mb-6">
    <h3 className="flex items-center gap-2 font-medium text-blue-800 mb-2">
      <Shield className="h-5 w-5" />
      Google Cloud Security - Web Risk Submission API : Submission Guidelines
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
);

// The main form for submitting URLs
const SubmissionForm = ({ onSubmit }) => {
  const [url, setUrl] = useState('');
  const [evidence, setEvidence] = useState('');
  const [submissionType, setSubmissionType] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

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
          url,
          evidence,
          type: submissionType
        })
      });
      
      const data = await response.json();
      
      if (data.operation) {
        // Call the parent handler with submission details
        onSubmit({
          url,
          operation: data.operation,
          timestamp: data.timestamp,
          evidence,
          type: submissionType,
          status: 'PENDING'
        });
        
        // Reset form
        setUrl('');
        setEvidence('');
        setSubmissionType('');
      }
    } catch (error) {
      console.error('Submission error:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Help text changes based on selected submission type
  const getEvidencePlaceholder = () => {
    switch (submissionType) {
      case 'phishing':
        return "Describe how this site impersonates a legitimate brand. Include:\n- Brand being impersonated\n- Deceptive elements (logo, login page, etc.)\n- Type of credentials being requested";
      case 'malware':
        return "Describe the malware being distributed. Include:\n- Executable name/location\n- Observed malicious behavior\n- Any additional indicators";
      default:
        return "Select a submission type to see guidance...";
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Submission Type
        </label>
        <select
          value={submissionType}
          onChange={(e) => setSubmissionType(e.target.value)}
          className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
          required
        >
          <option value="">Select type...</option>
          <option value="phishing">Phishing/Social Engineering</option>
          <option value="malware">Malware Distribution</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          URL to Submit
        </label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
          placeholder="Enter suspicious URL..."
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Evidence of Violation
        </label>
        <textarea
          value={evidence}
          onChange={(e) => setEvidence(e.target.value)}
          className="w-full px-4 py-2 border rounded-md focus:ring-2 focus:ring-blue-500"
          placeholder={getEvidencePlaceholder()}
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
  );
};

// Component to display submission history and status
const SubmissionHistory = ({ submissions, onRefreshStatus }) => {
  const getStatusDisplay = (status) => {
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
          text: 'Not added to blocklist',
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

  return (
    <div className="mt-8">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium">Submission History</h3>
        <button
          onClick={onRefreshStatus}
          className="text-sm text-blue-600 hover:text-blue-800"
        >
          Refresh Status
        </button>
      </div>
      
      <div className="space-y-4">
        {submissions.length === 0 ? (
          <p className="text-center text-gray-500 py-8">
            No submissions yet. Submit a URL above to get started.
          </p>
        ) : (
          submissions.map((submission) => {
            const status = getStatusDisplay(submission.status);
            return (
              <div key={submission.operation} className="bg-gray-50 rounded-lg p-4 border">
                <div className="flex justify-between items-start">
                  <div className="space-y-2">
                    <div className="font-medium break-all">{submission.url}</div>
                    <div className="text-sm text-gray-500">
                      Submitted: {new Date(submission.timestamp).toLocaleString()}
                    </div>
                    <div className="text-sm">
                      Type: {submission.type}
                    </div>
                  </div>
                  <div className={`flex items-center gap-2 px-3 py-1 rounded-full ${status.className}`}>
                    {status.icon}
                    <span className="text-sm">{status.text}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

// Main submission tab component that combines all pieces
const SubmissionTab = () => {
  const [submissions, setSubmissions] = useState([]);

  // Add a new submission to the list
  const handleSubmit = (submission) => {
    setSubmissions([submission, ...submissions]);
  };

  // Refresh the status of all pending submissions
  const refreshSubmissionStatus = async () => {
    const updatedSubmissions = await Promise.all(
      submissions.map(async (submission) => {
        if (submission.status === 'PENDING') {
          try {
            const response = await fetch(`/api/submission/${submission.operation}`);
            const data = await response.json();
            return { ...submission, status: data.status };
          } catch (error) {
            console.error('Error updating status:', error);
            return submission;
          }
        }
        return submission;
      })
    );
    
    setSubmissions(updatedSubmissions);
  };

  return (
    <div className="p-6">
      <SubmissionGuidelines />
      <SubmissionForm onSubmit={handleSubmit} />
      <SubmissionHistory 
        submissions={submissions} 
        onRefreshStatus={refreshSubmissionStatus} 
      />
    </div>
  );
};

export default SubmissionTab;
