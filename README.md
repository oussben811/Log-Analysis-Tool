# Security Log Analysis Tool

## Overview
The Security Log Analysis Tool is a Python-based security utility designed to analyze log files for suspicious patterns and potential security threats. This tool helps security professionals and system administrators identify and respond to security incidents by automatically detecting and alerting on suspicious activities in log files.

## Features
- 🔍 **Pattern-based Detection**: Configurable patterns for detecting various security events
- 📊 **Real-time Analysis**: Processes log files with line-by-line analysis
- 🚨 **Alert Generation**: Creates detailed alerts for detected security events
- 📈 **Statistics Tracking**: Maintains counts and summaries of detected patterns
- 📝 **Comprehensive Logging**: Detailed logging of analysis activities and findings
- 📤 **Export Capabilities**: Exports results in JSON format for further analysis
- ⚙️ **Configurable Patterns**: Easy-to-modify JSON configuration for detection patterns

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (for cloning the repository)

### Setup
1. Clone the repository:
```bash
git clone https://github.com/oussben811/log-analysis-tool.git
cd log-analysis-tool
```

2. Create a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```python
from log_analyzer import LogAnalyzer

# Initialize the analyzer
analyzer = LogAnalyzer(config_file="config/patterns.json")

# Analyze a log file
analyzer.analyze_log_file("path/to/your/logfile.log")

# Export the results
analyzer.export_results("analysis_results.json")
```

### Configuration
The tool uses a JSON configuration file for defining detection patterns. Default patterns include:
- Failed login attempts
- SQL injection attempts
- XSS attempts
- Suspicious file access
- Admin login events
- Port scanning
- Brute force attempts
- Malware detection
- Privilege escalation

You can modify the patterns in `config/patterns.json`:
```json
{
    "pattern_name": "regex_pattern",
    "failed_login": "Failed login.*from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
}
```

### Output Format
The tool generates JSON output containing:
- Timestamp of analysis
- Total number of alerts
- Statistics for each pattern
- Detailed alert information

Example output:
```json
{
    "timestamp": "2024-10-27T10:00:00",
    "total_alerts": 42,
    "statistics": {
        "failed_login": 15,
        "sql_injection": 3,
        "xss_attempt": 1
    },
    "alerts": [
        {
            "timestamp": "2024-10-27T09:45:00",
            "pattern": "failed_login",
            "line_number": 1337,
            "log_file": "auth.log",
            "content": "Failed login attempt from 192.168.1.100",
            "matches": ["192.168.1.100"]
        }
    ]
}
```

## Extending the Tool

### Adding New Patterns
1. Open `config/patterns.json`
2. Add new pattern entries:
```json
{
    "new_pattern_name": "your_regex_pattern"
}
```

### Custom Alert Handling
Modify the `_handle_alert` method in `LogAnalyzer` class to implement custom alert handling:
```python
def _handle_alert(self, alert):
    # Add custom handling logic
    pass
```

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Considerations
- This tool is for defensive security analysis only
- Test patterns thoroughly before deployment
- Ensure proper access controls on log files
- Review results for false positives

## Acknowledgments
- Built with security best practices in mind
- Inspired by real-world security monitoring needs
- Community contributions welcome

## Support
For support, please:
1. Check existing issues in the repository
2. Create a new issue with detailed information
3. Include relevant log samples (sanitized)

## Roadmap
- [ ] Add machine learning-based pattern detection
- [ ] Implement real-time monitoring capabilities
- [ ] Add support for more log formats
- [ ] Create visualization dashboard
- [ ] Add automated response capabilities

## Author
- GitHub: [@oussben811](https://github.com/oussben811)
- Looking at your GitHub profile, I can see you're interested in cybersecurity projects. Feel free to reach out if you need help with this tool or want to collaborate on other security projects.

## Project Status
🚧 This project is currently under active development. Contributors and feedback are welcome!
