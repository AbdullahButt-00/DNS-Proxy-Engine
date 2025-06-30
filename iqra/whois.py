import whois
from datetime import datetime
from collections import defaultdict
import math

# Simulate part of the class manually
class SimpleDomainScorer:
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.ru', '.su', '.xyz', '.top',
            '.work', '.click', '.download', '.stream', '.bid', '.science'
        }
        self.legitimate_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil'}
        self.domain_cache = {}

    def calculate_domain_age_score(self, domain):
        try:
            if domain in self.domain_cache:
                return self.domain_cache[domain]['age_score']
            
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age_days = (datetime.now() - creation_date).days
                score = min(1.0, age_days / 365.0)  # Normalize: full score if ≥1 year old

                self.domain_cache[domain] = {'age_score': score}
                return score
        except:
            return 0.2  # Fallback if WHOIS fails

    def calculate_tld_score(self, domain):
        tld = '.' + domain.split('.')[-1].lower()
        if tld in self.legitimate_tlds:
            return 0.9
        elif tld in self.suspicious_tlds:
            return 0.1
        else:
            return 0.6  # Neutral

# --- Testing Block ---
if __name__ == "__main__":
    scorer = SimpleDomainScorer()
    
    test_domains = [
        "google.com",
        "example.xyz",
        "suspicious.ru",
        "legit.org",
        "newdomain2025.tk"
    ]
    
    for domain in test_domains:
        age_score = scorer.calculate_domain_age_score(domain)
        tld_score = scorer.calculate_tld_score(domain)
        print(f"Domain: {domain}")
        print(f" - Age Score: {age_score:.2f}")
        print(f" - TLD Score: {tld_score:.2f}")
        print("-----")
        #print(f"Domain: {domain}")
        print(f" - Age Score: {age_score:.2f} {'(LOW)' if age_score < 0.5 else '(HIGH)'}")
        print(f" - TLD Score: {tld_score:.2f} {'(Suspicious)' if tld_score < 0.2 else 'OK'}")
        print("-" * 50)


