
import json

def parse_results(scan_results):
    # Parse OWASP ZAP and Burp Suite scan results
    vulnerabilities = []
    for result in scan_results:
        if result['severity'] == 'high':
            vulnerabilities.append({
                'id': result['id'],
                'description': result['description'],
                'severity': result['severity'],
            })
    return vulnerabilities



