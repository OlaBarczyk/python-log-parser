## Python Log Parser

Educational project for parsing and analyzing system log files.
Includes both a simple log reader and an SSH brute-force detection module.

Features
### 1. Log Reader (log_parser.py)

Reads log files line by line

Optional keyword filtering

Handles encoding issues and common file errors

Useful for quick exploration of system logs

### 2. SSH Brute-force Detector (detect_bruteforce.py)

Detects repeated failed SSH login attempts

Sliding time-window brute-force model

Generates:

alerts.json — detected brute-force attempts

stats.json — per-IP statistics for SOC analysis

Extracts:

total number of failed logins

unique attacking IPs

top N attackers

timestamps + example log lines

## Usage
### 1. Read and print logs
python log_parser.py /path/to/logfile.log


With keyword filtering:

python log_parser.py /var/log/syslog error

### 2. Detect SSH brute-force attacks
python detect_bruteforce.py sample_logs/auth.log 5 5


Where:

5 → number of failures required to trigger an alert

5 → sliding window in minutes

The script generates:

alerts.json
stats.json

Example Output
Wrote 3 alert(s) to alerts.json
Wrote stats to stats.json

Summary:
  Total failed logins: 128
  Unique source IPs  : 17
  Top attackers:
         185.199.110.2  ->  36 failures
         46.72.91.44    ->  22 failures
         182.15.9.77    ->  18 failures

## Author

Aleksandra Barczyk
Demo project for SOC / Blue Team / IT Security analysis.
