from log_analyzer import LogAnalyzer

# Initialize the analyzer
analyzer = LogAnalyzer(config_file="config/patterns.json")

# Analyze a log file
analyzer.analyze_log_file("path/to/your/logfile.log")

# Export the results
analyzer.export_results("analysis_results.json")