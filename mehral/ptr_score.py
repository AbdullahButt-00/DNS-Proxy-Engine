import socket

def ptr_score(domain):
    try:
        ip = socket.gethostbyname(domain)
        ptr = socket.gethostbyaddr(ip)
        return 0.0  # PTR found — no problem
    except Exception:
        return 0.2  # PTR missing or failed — mildly suspicious
print("google.com PTR:", ptr_score("google.com"))     # Likely 0.0
print("randomxyzqwe.com PTR:", ptr_score("randomxyzqwe.com"))  # Likely 0.2