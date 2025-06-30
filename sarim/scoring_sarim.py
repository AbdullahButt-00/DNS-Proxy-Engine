# Importing necessary libraries
import random
import os

# Ml Score function:
def ml_score(domain: str) -> float:
    """Returns a simulated ML score between 0 (malicious) and 1 (safe)."""
    return round(random.uniform(0.1,0.9),2)

# Loads blacklist.txt from the same folder as this script, regardless of where it's run from
def load_threat_intel(filepaths=[
    os.path.join(os.path.dirname(__file__), "blacklist.txt"),
    os.path.join(os.path.dirname(__file__), "test.txt")]) -> set:
    
    # making a set
    combined = set()

    # looping over file(s) and opening in read mode
    for filepath in filepaths:
        try:
            with open(filepath,"r") as f:
                for line in f:
                    domain = line.strip().lower()
                    combined.add(domain)
        except FileNotFoundError:
            continue # we can add a log error here too

    return combined 

blacklist = load_threat_intel()
# debug:
print("Loaded blacklist:", blacklist)

# Making Threat Intel Function:
def threat_intel_score(domain: str) -> float:
    """Returns a score based on threat feed presence."""
    if domain.lower() in blacklist:
        return 0.2
    else:
        return 1.0


if __name__ == "__main__":
    
    test_domains = ["google.com", "malicious-site.ru", "random123.biz","badactor.net"]
    
    for domain in test_domains:
        ml = ml_score(domain)
        threat = threat_intel_score(domain)
        print(f"{domain} → ML Score: {ml} | Threat Intel Score: {threat}")
