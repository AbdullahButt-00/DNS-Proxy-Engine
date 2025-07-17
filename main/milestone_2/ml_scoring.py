# from transformers import AutoTokenizer, AutoModelForSequenceClassification
# import torch, torch.nn.functional as F

# _MODEL = "kmack/malicious-url-detection"
# _tok   = AutoTokenizer.from_pretrained(_MODEL)
# _net   = AutoModelForSequenceClassification.from_pretrained(_MODEL)
# _net.eval()

# def compute_ml_score(domain: str) -> float:
#     """
#     Returns P(malicious) in [0,1] for a bare domain/host.
#     Higher → more likely malicious.
#     """
#     text   = domain.strip().lower()           # required by model
#     with torch.no_grad():
#         logits = _net(**_tok(text, return_tensors="pt")).logits
#         probs  = F.softmax(logits, dim=1)[0]
#         # index 1 = 'MALWARE' (see config.json); index 0 = BENIGN
#         return round(probs[1].item(), 4)
