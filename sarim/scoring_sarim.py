# Importing necessary libraries
import random
import os

# Ml Score function:
def ml_score(domain: str) -> float:
    """Returns a simulated ML score between 0 (malicious) and 1 (safe)."""
    return round(random.uniform(0.1,0.9),2)

# Loads the necessary files
def load_threat_intel(filepaths: list) -> set:
    """Loads domains from a list of files and returns a combined set."""
    combined = set()
    for filepath in filepaths:
        try:
            with open(filepath, "r") as f:
                for line in f:
                    domain = line.strip().lower()
                    combined.add(domain)
        except FileNotFoundError:
            continue
    return combined

# Load threat intel files once
bad_domains = load_threat_intel(["malicious_domains_cache.txt"])
good_domains = load_threat_intel(["good_domains_cache.txt"])

# Making Threat Intel Function:
def threat_intel_score(domain: str) -> float:
    """Score based on threat intel sets preloaded from cache files."""
    domain = domain.lower()
    if domain in bad_domains:
        return 0.2
    elif domain in good_domains:
        return 1.0
    else:
        return 0.5  # Unknown



if __name__ == "__main__":
    # Get 5 sample domains from each set
    bad_sample = list(bad_domains)[:5]
    good_sample = list(good_domains)[:5]
    unknown_sample = ["totallyunknownxyz.example"]

    test_domains = bad_sample + good_sample + unknown_sample

    # Print header
    print(f"{'Domain':<60} | {'ML Score':<8} | {'Threat Intel Score'}")
    print("-" * 90)

    # Print scores in aligned format
    for domain in test_domains:
        ml = ml_score(domain)
        threat = threat_intel_score(domain)
        print(f"{domain:<60} | {ml:<8} | {threat}")
