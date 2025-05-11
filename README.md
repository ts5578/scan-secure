# ScanSecure - A secure code review application
## Overview

ScanSecure is an AI-powered code vulnerability scanner that helps developers identify security risks in their codebase. It combines machine learning models with generative AI to detect vulnerabilities like SQL injection, cross-site scripting (XSS), and buffer overflows.

## Features

- **Multi-language Support**: Analyzes Python, JavaScript, Java, C/C++, Go, PHP, Ruby, and TypeScript code
- **GitHub Integration**: Scan entire repositories or specific files
- **AI-Powered Analysis**: Uses CodeBERT and Gemini AI for accurate vulnerability detection
- **Real-time Progress Tracking**: Monitor scan progress with live updates
- **Detailed Reports**: Get vulnerability details with code snippets and remediation suggestions

## Prerequisites

Before you begin, ensure you have the following installed:

- Node.js (v16 or higher)
- Python (v3.8 or higher)
- npm (v8 or higher)
- Git

## Installation

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ScanSecure.git
   cd ScanSecure/backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file with your:
   - GitHub OAuth credentials
   - Gemini API key
   - Flask secret key

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

## Running the Application

1. Start the backend server (from backend directory):
   ```bash
   python app.py
   ```

2. Start the frontend development server (from frontend directory):
   ```bash
   npm start
   ```

3. The application should automatically open in your default browser at `http://localhost:3000`

## Usage Instructions

### Scanning Code

1. **Connect with GitHub**:
   - Click "Connect with GitHub" to authenticate
   - Grant the necessary permissions

2. **Select a scanning method**:
   - **Paste code directly**: Enter your code in the text area
   - **Upload a file**: Click "Upload a file" and select your code file
   - **GitHub repository**: Select a repository from the dropdown or enter a GitHub URL

3. **Start scanning**:
   - Click "Scan for Vulnerabilities"
   - View real-time progress

4. **Review results**:
   - Vulnerabilities will be highlighted with details
   - View the scan summary for statistics

### Understanding Results

- **Safe Code**: Green indicator with "Code is safe" message
- **Vulnerabilities Detected**: Red indicator with vulnerability type
- **Error**: Yellow indicator with error details
- **Summary**: Overview of files scanned and vulnerabilities found

## Configuration

### Backend Configuration

Edit the `.env` file in the backend directory to configure:

```ini
FLASK_SECRET_KEY=your_secret_key
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=http://localhost:5000/github/callback
GEMINI_API_KEY=your_gemini_api_key
```

### Frontend Configuration

Edit `src/config.js` to configure API endpoints:

```javascript
export const API_BASE_URL = 'http://localhost:5000';
```

## Troubleshooting

### Common Issues

1. **GitHub Authentication Fails**:
   - Ensure your GitHub OAuth app is properly configured
   - Check callback URL matches your `.env` setting

2. **No Files Found in Repository**:
   - Verify the repository contains files with supported extensions
   - Check file permissions in the repository

3. **AI Analysis Errors**:
   - Verify your Gemini API key is valid
   - Check your internet connection

4. **CORS Errors**:
   - Ensure backend is running on the correct port
   - Verify frontend is making requests to the right endpoint

## Software Architecture

```
ScanSecure/
├── backend/               # Flask server
│   ├── app.py            # Main application
│   ├── requirements.txt  # Python dependencies
│   └── .env              # Environment configuration
│
├── frontend/             # React application
│   ├── public/           # Static assets
│   ├── src/              # React components
│   │   ├── App.js        # Main component
│   │   └── styles.css    # Application styles
│   └── package.json      # Frontend dependencies
│
└── README.md             # This documentation
```



## License

Distributed under the MIT License. See `LICENSE` for more information.

