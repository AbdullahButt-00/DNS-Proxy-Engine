# test_dns.py
import socket
from dnslib import DNSRecord

q = DNSRecord.question("0-hubs.iosdm.net")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)

# Send to your local proxy running on port 5300
sock.sendto(q.pack(), ("192.168.18.177", 5300))

data, _ = sock.recvfrom(4096)
print(DNSRecord.parse(data))
