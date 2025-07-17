# ml_api.py  – run with:  uvicorn ml_api:app --host 127.0.0.1 --port 8500
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch, torch.nn.functional as F

_MODEL = "kmack/malicious-url-detection"
_tok   = AutoTokenizer.from_pretrained(_MODEL)
_net   = AutoModelForSequenceClassification.from_pretrained(_MODEL)
_net.eval()

class Item(BaseModel):
    domain: str

app = FastAPI()

@app.post("/score")
def score(item: Item):
    try:
        txt = item.domain.strip().lower()
        with torch.no_grad():
            logits = _net(**_tok(txt, return_tensors="pt")).logits
            probs  = F.softmax(logits, dim=1)[0]
        return {"ml_badness": float(probs[1])}   # idx 1 = malicious
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/")
def root():
    return {"status": "ML scoring API is live."}

