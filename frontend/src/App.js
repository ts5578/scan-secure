import React, { useState, useEffect } from 'react';
import './style.css';

function App() {
  const [code, setCode] = useState('');
  const [file, setFile] = useState(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [results, setResults] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [showRepoSelector, setShowRepoSelector] = useState(false);
  const [scanProgress, setScanProgress] = useState({
    scanned: 0,
    total: 0,
    status: 'idle'
  });

  useEffect(() => {
    checkAuthStatus();
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      fetchRepos();
    }
  }, [isAuthenticated]);

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('http://localhost:5000/github/status', {
        credentials: 'include'
      });
      if (!response.ok) throw new Error('Failed to check auth status');
      const data = await response.json();
      setIsAuthenticated(data.authenticated);
    } catch (error) {
      console.error('Auth check error:', error);
      setError('Failed to check GitHub connection status');
    }
  };

  const fetchRepos = async () => {
    try {
      const response = await fetch('http://localhost:5000/github/repos', {
        credentials: 'include'
      });
      const data = await response.json();
      if (data.repos) {
        setRepos(data.repos);
        setShowRepoSelector(true);
      }
    } catch (error) {
      setError('Failed to fetch repositories');
    }
  };

  const handleGithubLogin = () => {
    setError(null);
    window.location.href = `http://localhost:5000/github/login?ts=${Date.now()}`;
  };

  const handleGithubLogout = async () => {
    try {
      const response = await fetch('http://localhost:5000/github/logout', { 
        method: 'POST',
        credentials: 'include'
      });
      if (!response.ok) throw new Error('Logout failed');
      setIsAuthenticated(false);
      setShowRepoSelector(false);
      setRepos([]);
      setSelectedRepo('');
    } catch (error) {
      console.error('Logout error:', error);
      setError('Failed to disconnect from GitHub');
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setCode('');
    setGithubUrl('');
    setSelectedRepo('');
  };

  const handleRepoChange = (e) => {
    setSelectedRepo(e.target.value);
    setCode('');
    setFile(null);
    setGithubUrl('');
  };

  const handleRepoScan = async () => {
    if (!selectedRepo) {
      setError('Please select a repository');
      return;
    }
    
    setLoading(true);
    setError(null);
    setResults([]);
    setScanProgress({
      scanned: 0,
      total: 0,
      status: 'scanning'
    });

    try {
      const response = await fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ github_url: `https://github.com/${selectedRepo}` })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Repository scan failed');
      }

      const data = await response.json();
      
      if (!data.results || data.results.length === 0) {
        throw new Error(data.error || 'No supported files found in repository');
      }
      
      setResults(data.results);
      setScanProgress({
        scanned: data.summary?.total_files || data.results.length,
        total: data.summary?.total_files || data.results.length,
        status: 'complete'
      });
      
      if (data.summary) {
        setResults(prev => [
          ...prev,
          {
            summary: true,
            message: `Scan complete: ${data.summary.total_files} files scanned, ${data.summary.vulnerable_files} with vulnerabilities`,
            totalFiles: data.summary.total_files,
            vulnerableFiles: data.summary.vulnerable_files
          }
        ]);
      }
    } catch (error) {
      console.error('Repository scan error:', error);
      setError(error.message);
      setResults([{ 
        result: `Error: ${error.message}`,
        error: true 
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResults([]);
    setScanProgress({
      scanned: 0,
      total: 0,
      status: 'idle'
    });

    try {
      let response;
      
      if (file) {
        const formData = new FormData();
        formData.append('file', file);
        response = await fetch('http://localhost:5000/analyze', {
          method: 'POST',
          body: formData,
          credentials: 'include'
        });
      } else if (code) {
        response = await fetch('http://localhost:5000/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code }),
          credentials: 'include'
        });
      } else if (githubUrl) {
        if (!githubUrl.includes('github.com/')) {
          throw new Error('Please enter a valid GitHub URL');
        }
        response = await fetch('http://localhost:5000/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ github_url: githubUrl }),
          credentials: 'include'
        });
      } else {
        throw new Error('Please provide code, file, or GitHub URL');
      }

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Analysis failed');
      }

      const data = await response.json();
      setResults(data.results || [data]);
      
    } catch (error) {
      console.error('Analysis error:', error);
      setError(error.message);
      setResults([{ 
        result: `Error: ${error.message}`,
        error: true 
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>ScanSecure Code Vulnerability Scanner</h1>
      
      {error && (
        <div className="error">
          {error}
          <button onClick={() => setError(null)} className="dismiss-btn">
            ×
          </button>
        </div>
      )}
      
      <div className="auth-section">
        {isAuthenticated ? (
          <button onClick={handleGithubLogout} className="github-btn">
            Disconnect GitHub
          </button>
        ) : (
          <button onClick={handleGithubLogin} className="github-btn">
            Connect with GitHub
          </button>
        )}
        {isAuthenticated && <span className="auth-status">✓ Connected to GitHub</span>}
      </div>

      {showRepoSelector && (
        <div className="repo-selector">
          <h3>Select a GitHub Repository to Scan</h3>
          <select 
            value={selectedRepo}
            onChange={handleRepoChange}
            className="repo-dropdown"
          >
            <option value="">-- Select Repository --</option>
            {repos.map(repo => (
              <option key={repo.full_name} value={repo.full_name}>
                {repo.private ? '🔒 ' : '🌍 '}{repo.full_name}
              </option>
            ))}
          </select>
          
          <button 
            onClick={handleRepoScan}
            disabled={!selectedRepo || loading}
            className="scan-btn"
          >
            {loading ? 'Scanning...' : 'Scan Repository'}
          </button>
        </div>
      )}

      {scanProgress.status === 'scanning' && (
        <div className="scan-progress">
          <h4>Scanning repository...</h4>
          <progress 
            value={scanProgress.scanned} 
            max={scanProgress.total || 100} 
          />
          <p>
            {scanProgress.scanned} files scanned
            {scanProgress.total > 0 && ` of ${scanProgress.total}`}
          </p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="scan-form">
        <div className="input-group">
          <label>Paste your code:</label>
          <textarea
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
              setFile(null);
              setGithubUrl('');
              setSelectedRepo('');
            }}
            placeholder="Paste your code here..."
            rows={10}
          />
        </div>

        <div className="or-divider">OR</div>

        <div className="input-group">
          <label>Upload a file:</label>
          <input 
            type="file" 
            onChange={handleFileChange}
            accept=".py,.js,.java,.c,.cpp,.go,.php,.rb,.ts,.html"
          />
        </div>

        <div className="or-divider">OR</div>

        <div className="input-group">
          <label>GitHub repository or file URL:</label>
          <input
            type="text"
            value={githubUrl}
            onChange={(e) => {
              setGithubUrl(e.target.value);
              setCode('');
              setFile(null);
              setSelectedRepo('');
            }}
            placeholder="https://github.com/username/repo/path/to/file"
            disabled={!isAuthenticated}
          />
          {!isAuthenticated && <p className="hint">Connect with GitHub to scan repositories</p>}
        </div>

        <button 
          type="submit" 
          disabled={loading || (!code && !file && !githubUrl)}
          className="scan-btn"
        >
          {loading ? 'Scanning...' : 'Scan for Vulnerabilities'}
        </button>
      </form>

      {loading && <div className="loading">Analyzing code...</div>}

      <div className="results">
        {results
          .filter(result => !result.summary)
          .map((result, index) => (
            <div key={index} className={`result-card ${result.error ? 'error' : ''}`}>
              {result.file && <h3>File: {result.file}</h3>}
              {result.code_snippet && (
                <div className="code-snippet">
                  <pre>{result.code_snippet}</pre>
                </div>
              )}
              <div className={`result-message ${result.result?.includes('safe') ? 'safe' : 'unsafe'}`}>
                {result.result}
                {result.vulnerability && (
                  <div className="vulnerability">
                    <strong>Type:</strong> {result.vulnerability}
                  </div>
                )}
              </div>
            </div>
          ))}
        
        {results.find(r => r.summary) && (
          <div className="result-card summary">
            <div className="summary-message">
              <h3>Scan Summary</h3>
              <p>{results.find(r => r.summary).message}</p>
              <div className="stats">
                <div className="stat">
                  <span className="stat-number">{results.find(r => r.summary).totalFiles}</span>
                  <span className="stat-label">Files Scanned</span>
                </div>
                <div className="stat">
                  <span className="stat-number">{results.find(r => r.summary).vulnerableFiles}</span>
                  <span className="stat-label">Vulnerable Files</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;