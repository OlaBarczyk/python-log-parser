# Python Log Parser
Educational project for parsing and analyzing system logs.
## Features
- **Log Reader:** Parses and prints system log lines from file (`log_parser.py`).
- **SSH Brute-force Detector:** Detects multiple failed SSH login attempts from the same IP in a short time window and generates `alerts.json`.

## Usage
```bash
*** Read and print logs
python log_parser.py /path/to/logfile.log

*** Detect brute-force SSH attacks
python detect_bruteforce.py sample_logs/auth.log 5 5
```
## Example Output

Wrote 1 alert(s) to alerts.json

## Author
Aleksandra Barczyk - demo project for SOC / IT Security analysis.
