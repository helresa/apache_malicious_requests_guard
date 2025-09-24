
# Apache Malicious Requests Guard
--------------------------------
Tail one or more Apache access logs (file or directory), detect likely-malicious requests
(SQLi, XSS, path traversal, WordPress probes, env file grabs, phpMyAdmin scans, etc.).
When an IP exceeds a configurable threshold within a rolling time window, execute a
system command to block it (e.g., iptables/ufw/firewall-cmd).

Compatible with Python 3.5+ (no capture_output).

## Examples
--------
### Dry run from start of file, block after 10 hits in 5 minutes
python3 apache-malicious-requests-guard.py \
  --log /var/log/apache2/access.log \
  --threshold 10 --window 300 --from-start --dry-run

### Tail all logs in a directory (e.g. cPanel domlogs)
python3 apache-malicious-requests-guard.py \
  --log /var/log/apache2/domlogs \
  --threshold 15 --window 300
