import re
import json
from datetime import datetime
from collections import defaultdict
import logging
from pathlib import Path

class LogAnalyzer:
    def __init__(self, config_file="config/patterns.json"):
        """
        Initialize the log analyzer with configuration settings
        
        Args:
            config_file (str): Path to the configuration file containing detection patterns
        """
        self.suspicious_patterns = self._load_patterns(config_file)
        self.alerts = []
        self.stats = defaultdict(int)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_analysis.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_patterns(self, config_file):
        """Load suspicious patterns from configuration file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default patterns if config file not found
            return {
                "failed_login": r"Failed login.*from (\d+\.\d+\.\d+\.\d+)",
                "sql_injection": r"(SELECT|UNION|DROP|INSERT).*('|;)",
                "xss_attempt": r"(<script>|alert\(|eval\()",
                "file_access": r"(\.\.\/|\/etc\/passwd|\/etc\/shadow)",
                "admin_login": r"admin.*login.*successful"
            }

    def analyze_log_file(self, log_file):
        """
        Analyze a log file for suspicious patterns
        
        Args:
            log_file (str): Path to the log file to analyze
        """
        try:
            with open(log_file, 'r') as f:
                for line_number, line in enumerate(f, 1):
                    self._analyze_line(line, line_number, log_file)
            
            self._generate_summary()
        except Exception as e:
            self.logger.error(f"Error analyzing log file {log_file}: {str(e)}")

    def _analyze_line(self, line, line_number, log_file):
        """Analyze a single log line for suspicious patterns"""
        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                self.stats[pattern_name] += 1
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'pattern': pattern_name,
                    'line_number': line_number,
                    'log_file': log_file,
                    'content': line.strip(),
                    'matches': matches
                }
                self.alerts.append(alert)
                self._handle_alert(alert)

    def _handle_alert(self, alert):
        """Handle detected alerts"""
        severity = self._determine_severity(alert['pattern'])
        self.logger.warning(
            f"[{severity}] {alert['pattern']} detected in {alert['log_file']} "
            f"at line {alert['line_number']}"
        )

    def _determine_severity(self, pattern_name):
        """Determine alert severity based on pattern"""
        high_severity = ['sql_injection', 'admin_login']
        medium_severity = ['failed_login', 'xss_attempt']
        
        if pattern_name in high_severity:
            return 'HIGH'
        elif pattern_name in medium_severity:
            return 'MEDIUM'
        return 'LOW'

    def _generate_summary(self):
        """Generate analysis summary"""
        self.logger.info("\n=== Analysis Summary ===")
        self.logger.info(f"Total alerts generated: {len(self.alerts)}")
        for pattern, count in self.stats.items():
            self.logger.info(f"{pattern}: {count} occurrences")

    def export_results(self, output_file="analysis_results.json"):
        """
        Export analysis results to a JSON file
        
        Args:
            output_file (str): Path to the output file
        """
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'total_alerts': len(self.alerts),
                'statistics': dict(self.stats),
                'alerts': self.alerts
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            self.logger.info(f"Analysis results exported to {output_file}")
        except Exception as e:
            self.logger.error(f"Error exporting results: {str(e)}")