from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
import re
import numpy as np
from sklearn.linear_model import LogisticRegression

app = FastAPI(title="Zero Trust Firewall")

class URLItem(BaseModel):
    url: str

def extract_features(url):
    return [
        len(url),
        url.count("."),
        url.count("-") + url.count("@"),
        1 if url.startswith("https") else 0,
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0
    ]

data = [
    ("http://free-login-now.com", 1),
    ("http://192.168.1.1/login", 1),
    ("https://google.com", 0),
    ("https://github.com", 0),
]

X = np.array([extract_features(u) for u, y in data])
y = np.array([y for u, y in data])

model = LogisticRegression()
model.fit(X, y)

logs = []

@app.post("/inspect_url")
def inspect(item: URLItem):
    features = np.array(extract_features(item.url)).reshape(1, -1)
    risk = model.predict_proba(features)[0][1]
    action = "BLOCK" if risk > 0.5 else "ALLOW"

    logs.append({"url": item.url, "action": action})

    return {
        "url": item.url,
        "risk_score": round(risk, 2),
        "action": action
    }

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html = "<h2>Zero Trust Firewall Dashboard</h2><table border=1>"
    html += "<tr><th>URL</th><th>Action</th></tr>"
    for l in logs:
        html += f"<tr><td>{l['url']}</td><td>{l['action']}</td></tr>"
    html += "</table>"
    return html
