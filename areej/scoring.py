# DNS-Proxy-Engine/areej/scoring_areej.py

import time
from collections import defaultdict

# Load the blacklist domains
with open("blacklist_domains.txt", "r") as f:
    blacklist = set(line.strip() for line in f)

# For tracking frequency of DNS requests
domain_query_log = defaultdict(list)

def blacklist_score(domain):
    """
    Returns 1.0 if the domain is in the blacklist, else 0.0
    """
    return 1.0 if domain in blacklist else 0.0

def query_frequency_score(domain, time_window=60, threshold=10):
    """
    Tracks how often a domain is queried in a time window.
    If the frequency is high, return a higher suspicious score.
    """
    current_time = time.time()
    domain_query_log[domain].append(current_time)

    # Remove old timestamps outside the time window
    domain_query_log[domain] = [
        ts for ts in domain_query_log[domain]
        if current_time - ts <= time_window
    ]

    count = len(domain_query_log[domain])
    if count > threshold:
        return min(1.0, (count - threshold) / threshold)
    return 0.0



# Test the blacklist function
print("Testing blacklist scoring:")
print("badsite.com:", blacklist_score("badsite.com"))  # Should return 1.0
print("google.com:", blacklist_score("google.com"))    # Should return 0.0

# Test the frequency scoring function
print("\nTesting frequency scoring:")
for i in range(12):
    score = query_frequency_score("test.com")
    print(f"Query {i+1} - Score: {score}")
    time.sleep(1)  # Sleep to simulate time gap between queries
