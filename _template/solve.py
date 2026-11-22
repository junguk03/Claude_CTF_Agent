#!/usr/bin/env python3
"""풀이 스크립트.

사용법: python3 solve.py http://대상 [--delay 0.5] [--proxy http://127.0.0.1:8080]

- 대상 주소는 인자로 받는다. scope.md의 대상 주소와 같은 호스트이거나 로컬(재현용)이어야 한다.
  로컬이 아니면 scope.md 필수 칸도 검사한다 (CLAUDE.md 2번).
- 요청마다 --delay 초 쉰다. 요청은 하나씩 순서대로 보낸다.
- 요청과 응답 원문은 out/NNN_메서드_경로.txt 로 저장한다. 번호는 이어서 붙고 덮어쓰지 않는다.
- 플래그 형식은 scope.md "플래그 형식"에서 읽어 응답마다 자동으로 찾는다.
- 세션은 Burp 값을 쓰지 말고 login()처럼 흐름을 따라 새로 받는다.
"""
import argparse
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

try:
    import requests
except ImportError:
    sys.exit("requests 모듈이 없다. requests가 설치된 파이썬으로 실행한다.")

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
SCOPE = HERE / "scope.md"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}

REQUIRED = ["종류", "대회 또는 플랫폼 이름", "문제 페이지 캡처 경로", "대상 주소",
            "대상 주소 확인", "플래그 형식", "AI 사용", "스캐너·퍼징", "다중 계정", "공유 인프라"]
REQUIRED_CONTEST = ["공식 페이지 주소"]
REQUIRED_WARGAME = ["문제 페이지 주소"]


# ---------- scope.md ----------
def read_scope():
    fields = {}
    if SCOPE.exists():
        for line in SCOPE.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^-\s*([^:]+?)\s*:\s*(.*)$", line)
            if m:
                fields.setdefault(m.group(1).strip(), m.group(2).strip().strip("`").strip())
    return fields


def scope_problems(f):
    kind = f.get("종류", "")
    need = list(REQUIRED)
    if "대회" in kind:
        need += REQUIRED_CONTEST
    elif "워게임" in kind:
        need += REQUIRED_WARGAME
    else:
        return ["종류 칸이 '대회' 또는 '워게임'이 아니다"]
    probs = [f"'{k}' 칸이 비었다" for k in need if not f.get(k)]
    if f.get("대상 주소 확인") and f["대상 주소 확인"] != "일치":
        probs.append("대상 주소 확인이 '일치'가 아니다")
    cap = f.get("문제 페이지 캡처 경로")
    if cap and not (HERE / cap).exists():
        probs.append(f"캡처 파일이 없다: {cap}")
    return probs


def host_port(url):
    u = urlsplit(url)
    return (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80)


def is_local(url):
    h = (urlsplit(url).hostname or "").lower()
    return h in LOCAL_HOSTS or h.endswith(".localhost")


def check_target(target, f):
    if not re.match(r"^https?://", target):
        sys.exit("대상 주소는 http:// 또는 https://로 시작해야 한다.")
    if is_local(target):
        print("[로컬 재현] 여기서 나온 플래그는 가짜다.")
        return
    probs = scope_problems(f)
    if probs:
        sys.exit("scope.md 문제로 대상에 요청하지 않는다:\n  - " + "\n  - ".join(probs))
    if host_port(target) != host_port(f["대상 주소"]):
        sys.exit(f"대상 주소가 scope.md와 다르다: {target} != {f['대상 주소']}")


def flag_regex(fmt):
    """'flag{...}', 'gctf{.*}', 'DH\\{.*\\}' 같은 형식을 정규식으로 바꾼다."""
    fmt = fmt.strip()
    if not fmt:
        return None
    if "{" in fmt:
        prefix = fmt.split("{", 1)[0].rstrip("\\")
        return re.compile(re.escape(prefix) + r"\{[^}\r\n]{1,300}\}")
    return re.compile(fmt)


# ---------- HTTP ----------
def next_index():
    nums = [int(p.name[:3]) for p in OUT.glob("[0-9][0-9][0-9]_*")]
    return max(nums, default=0) + 1


def slug(s):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
    return (s or "root")[:60]


def text_of(b):
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return str(b) if isinstance(b, str) else "<stream body>"


class Client:
    def __init__(self, base, delay, flag_re, proxy=None):
        self.base = base.rstrip("/") + "/"
        self.host = host_port(self.base)
        self.delay = delay
        self.flag_re = flag_re
        self.found = []
        self.n = next_index()
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0 (ctf-solve)"
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
            self.s.verify = False
            requests.packages.urllib3.disable_warnings()

    def req(self, method, path="", save=True, **kw):
        url = path if re.match(r"^https?://", path) else urljoin(self.base, path.lstrip("/"))
        if host_port(url) != self.host:
            raise ValueError(f"대상 밖 주소라 보내지 않는다: {url}")
        kw.setdefault("timeout", 15)
        kw.setdefault("allow_redirects", False)  # 다른 호스트로 넘어가지 않게. 필요하면 직접 따라간다.
        r = self.s.request(method, url, **kw)
        time.sleep(self.delay)
        name = self.save(r) if save else None
        print(f"[{method}] {urlsplit(url).path or '/'} -> {r.status_code} {len(r.content)}B {name or ''}")
        self.find_flag(r, name)
        return r

    def get(self, path="", **kw):
        return self.req("GET", path, **kw)

    def post(self, path="", **kw):
        return self.req("POST", path, **kw)

    def save(self, r):
        OUT.mkdir(exist_ok=True)
        p = r.request
        u = urlsplit(p.url)
        name = f"out/{self.n:03d}_{p.method}_{slug(u.path)}.txt"
        self.n += 1
        try:
            resp_headers = list(r.raw.headers.items())
        except Exception:
            resp_headers = list(r.headers.items())
        lines = [f"{p.method} {p.url}"]
        lines += [f"{k}: {v}" for k, v in p.headers.items()]
        lines += ["", text_of(p.body), "", "=" * 20 + " RESPONSE " + "=" * 20,
                  f"HTTP {r.status_code} {r.reason}"]
        lines += [f"{k}: {v}" for k, v in resp_headers]
        head = ("\n".join(lines) + "\n\n").encode("utf-8", "replace")
        (HERE / name).write_bytes(head + r.content)
        return name

    def find_flag(self, r, name):
        if not self.flag_re:
            return
        hay = r.text + "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        for m in set(self.flag_re.findall(hay)):
            self.found.append((m, name))
            print(f"[플래그 후보] {m}  ({name or '저장 안 함'})")


# ---------- 풀이 ----------
def login(c):
    """문제 인스턴스 안의 계정으로 새 세션을 받는다. 필요할 때 채운다."""
    pass


def solve(c):
    """여기에 풀이를 쓴다. 대조 요청(정상값)도 같이 보낸다."""
    r = c.get("/")
    print(r.headers.get("Server"), r.headers.get("X-Powered-By"), list(r.cookies.keys()))


def main():
    ap = argparse.ArgumentParser(description="CTF 풀이")
    ap.add_argument("target", help="대상 주소 (예: http://chall.example.com:1337)")
    ap.add_argument("--delay", type=float, default=0.5, help="요청 간격 초 (기본 0.5)")
    ap.add_argument("--proxy", help="Burp 등 프록시 (예: http://127.0.0.1:8080)")
    args = ap.parse_args()

    f = read_scope()
    check_target(args.target, f)
    fr = flag_regex(f.get("플래그 형식", ""))
    if not fr:
        print("[경고] scope.md에 플래그 형식이 없어 자동 감지를 하지 않는다.")
    c = Client(args.target, args.delay, fr, args.proxy)
    login(c)
    solve(c)
    if c.found:
        print("\n플래그 후보:")
        for m, name in c.found:
            print(f"  {m}  <- {name}")


if __name__ == "__main__":
    main()
