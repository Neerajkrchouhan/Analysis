import re
from collections import Counter, defaultdict
import csv

# Function to parse log lines
def parse_log_line(line):
    pattern = r'(?P<ip>[\d\.]+) .* "(?P<method>[A-Z]+) (?P<endpoint>\/\S*) HTTP\/1\.\d" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>.*)")?'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

# Count requests per IP
def count_requests_by_ip(log_data):
    ip_counts = Counter(entry['ip'] for entry in log_data)
    return ip_counts.most_common()

# Identify the most accessed endpoint
def count_endpoints(log_data):
    endpoint_counts = Counter(entry['endpoint'] for entry in log_data)
    return endpoint_counts.most_common(1)[0]

# Detect suspicious activity
def detect_suspicious_activity(log_data, threshold=10):
    failed_attempts = defaultdict(int)
    for entry in log_data:
        if entry['status'] == '401' or (entry.get('message') and "Invalid credentials" in entry['message']):
            failed_attempts[entry['ip']] += 1
    return [(ip, count) for ip, count in failed_attempts.items() if count > threshold]

# Write results to CSV
def write_to_csv(results, filename):
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for section, data in results.items():
                writer.writerow([section])  # Section title
                writer.writerow(data[0])    # Column headers
                writer.writerows(data[1:])  # Data rows
                writer.writerow([])         # Empty line between sections
    except Exception as e:
        print(f"Error writing to CSV: {e}")

# Main script
def main():
    log_file = "sample.log"
    log_data = []

    try:
        with open(log_file, 'r') as file:
            for line in file:
                parsed_line = parse_log_line(line)
                if parsed_line:
                    log_data.append(parsed_line)
    except FileNotFoundError:
        print(f"Error: The file {log_file} was not found.")
        return

    # Analyze log data
    ip_requests = count_requests_by_ip(log_data)
    most_accessed_endpoint = count_endpoints(log_data)
    suspicious_ips = detect_suspicious_activity(log_data)

    # Print results
    print("IP Address Requests:")
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")

    # Save to CSV
    results = {
        "Requests per IP": [["IP Address", "Request Count"]] + ip_requests,
        "Most Accessed Endpoint": [["Endpoint", "Access Count"], most_accessed_endpoint],
        "Suspicious Activity": [["IP Address", "Failed Login Count"]] + suspicious_ips,
    }
    write_to_csv(results, "log_analysis_results.csv")

if __name__ == "__main__":
    main()