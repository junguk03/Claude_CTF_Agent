#!/usr/bin/env python3
"""사용: python3 solve.py http://대상주소:포트
Burp로 보려면: PROXY=http://127.0.0.1:8080 python3 solve.py http://대상
"""
import os
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"
FLAG_RE = re.compile(r"Layer7\{[^}]{1,300}\}|[A-Za-z0-9_]{2,10}\{[^}]{3,200}\}")  # 대회 형식 우선
DELAY = float(os.environ.get("DELAY", "0.05"))  # 요청 사이 최소 간격(초). 대회 트래픽 규칙용
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)

s = requests.Session()
_last = [0.0]
_orig_request = s.request


def _throttled(*a, **k):
    wait = _last[0] + DELAY - time.time()
    if wait > 0:
        time.sleep(wait)
    _last[0] = time.time()
    return _orig_request(*a, **k)


s.request = _throttled
if os.environ.get("PROXY"):
    s.proxies = {"http": os.environ["PROXY"], "https": os.environ["PROXY"]}
    s.verify = False


def show(r, tag="resp", n=400):
    """응답 요약 출력 + 전체를 out/에 저장 + 플래그 자동 감지"""
    path = os.path.join(OUT, f"{int(time.time())}_{tag}.txt")
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(f"{r.request.method} {r.url}\n{r.status_code}\n{dict(r.headers)}\n\n{r.text}")
    print(f"[{r.status_code}] {r.request.method} {r.url}  len={len(r.text)}  -> {path}")
    print(r.text[:n])
    m = FLAG_RE.search(r.text)
    if m:
        print("\n*** FLAG 후보:", m.group(0))
    print("-" * 60)
    return r


def main():
    show(s.get(f"{BASE}/"), "index")
    # 다음 단계를 여기에 하나씩 추가


if __name__ == "__main__":
    main()
