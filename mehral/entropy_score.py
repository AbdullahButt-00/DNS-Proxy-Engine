import math

def shannon_entropy(s):
    """
    Calculates Shannon entropy of a string
    """
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy

def entropy_score(domain):
    """
    Returns the raw entropy value of the domain prefix
    """
    name = domain.split('.')[0]  # Only the part before the dot
    return shannon_entropy(name)


# Confirm the script runs
print("Testing entropy scoring...")
print("google.com:", entropy_score("google.com"))       # Should be low
print("x7z9w8e.com:", entropy_score("x7z9w8e.com"))     # Should be high
print("ajsk83jda.com:", entropy_score("ajsk83jda.com"))