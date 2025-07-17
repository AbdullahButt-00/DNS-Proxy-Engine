from ml_scoring import compute_ml_score
tests = ["google.com", "microsoft.com",
         "paypal-login.secure-access-update.ru",
         "bad-domain.xyz"]
for d in tests:
    print(f"{d:40}  ML_bad = {compute_ml_score(d)}")
