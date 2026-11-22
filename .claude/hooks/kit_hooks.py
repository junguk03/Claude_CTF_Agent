#!/usr/bin/env python3
"""웹 CTF 키트 hook. `.claude/settings.json`에서 부른다.

    python3 kit_hooks.py session     SessionStart        LESSONS.md와 최근 문제의 현재 상태를 넣는다
    python3 kit_hooks.py pre-bash    PreToolUse(Bash)    git add/commit/push, 범위 밖 호스트 요청을 막는다
    python3 kit_hooks.py pre-edit    PreToolUse(Write..) hook 파일과 settings.json 수정을 막는다
    python3 kit_hooks.py post        PostToolUse(*)      교훈 증상 대조, 플래그 후보, 가설 표 검사, 토큰 노출, 쓰기 검사, 30회 알림
    python3 kit_hooks.py post-fail   PostToolUseFailure  실패를 교훈과 대조하고, 처음 보는 실패는 기록한다
    python3 kit_hooks.py stop        Stop                기록 안 된 새 실패가 있으면 한 번 멈춘다
    python3 kit_hooks.py dismiss "이유"                  일회성 실패(오타 등)를 정리한다 (에이전트나 사람이 직접 실행)
    python3 kit_hooks.py check                           LESSONS.md 형식 검사

종료 코드: 0 통과, 2 차단(이유는 stderr로 Claude에게 간다).
hook 자체에 예상 못 한 오류가 나면 막지 않고 통과시킨다(종료 코드 1, stderr에 이유).
hook이 깨져서 모든 작업이 멈추는 일을 막기 위해서다 (LESSONS.md L04).
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
LESSONS = ROOT / "LESSONS.md"
STATE = ROOT / ".claude" / "state"
FAILURES = STATE / "failures.jsonl"
DISMISSED = STATE / "dismissed.jsonl"
COUNTER = STATE / "counter.json"
ALLOWED_HOSTS_FILE = ROOT / ".claude" / "allowed_hosts.txt"

NOTE_EVERY = 30                       # CLAUDE.md 5번: 도구 호출 30번마다 notes.md 정리
WRITE_CHECK_SUFFIXES = {".yml", ".yaml", ".sh", ".bash", ".nix"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}
PROTECTED = [".claude/hooks/", ".claude/settings.json", ".claude/allowed_hosts.txt"]

# scope.md 필수 칸 (_template/solve.py와 같게 유지)
REQUIRED = ["종류", "대회 또는 플랫폼 이름", "문제 페이지 캡처 경로", "대상 주소",
            "대상 주소 확인", "플래그 형식", "AI 사용", "스캐너·퍼징", "다중 계정", "공유 인프라"]

NET_TOOL_RE = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|socat|telnet|websocat|httpx|aiohttp|requests|urllib|fetch|"
    r"nmap|ffuf|gobuster|feroxbuster|dirsearch|nikto|sqlmap|s_client)\b")
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>`|;)\\]+", re.I)
NC_RE = re.compile(r"\b(?:nc|ncat|netcat|telnet)\s+(?:-\S+\s+)*([A-Za-z0-9.\-]+)\s+\d+")
CONNECT_RE = re.compile(r"-connect\s+([A-Za-z0-9.\-]+):\d+")
GIT_WRITE_RE = re.compile(r"\bgit\b[^;&|\n]*?\s(add|commit|push)\b")
EXIT_RE = re.compile(r"[Ee]xit (?:code|status) (\d+)")
NOMATCH_CMD_RE = re.compile(r"\b(grep|egrep|fgrep|rg|diff|cmp|test)\b|\[\s")

SECRET_RES = [
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("헤더 값", re.compile(r"(?im)^\s*(?:cookie|set-cookie|authorization)\s*:\s*(?![^\n]*(?:\*{3}|<가림>|REDACTED|\.\.\.))[^\n]{16,}")),
    ("쿠키·토큰 값", re.compile(
        r"(?i)\b(?:session|sessionid|session_id|connect\.sid|phpsessid|jsessionid|laravel_session|"
        r"token|access_token|refresh_token|auth)=([A-Za-z0-9%._\-]{16,})")),
]


# ---------- 입출력 ----------
def read_input():
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def context(event, parts):
    """Claude 컨텍스트에 덧붙인다(막지 않음)."""
    text = "\n\n".join(p for p in parts if p)
    if text:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}},
                         ensure_ascii=False))
    return 0


def block(parts):
    sys.stderr.write("\n\n".join(p for p in parts if p) + "\n")
    return 2


def strings_in(obj, skip=()):
    """JSON 값 안의 문자열을 모두 모은다."""
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in skip:
                out += strings_in(v, skip)
    elif isinstance(obj, list):
        for v in obj:
            out += strings_in(v, skip)
    elif obj is not None and not isinstance(obj, bool):
        out.append(str(obj))
    return out


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_jsonl(path):
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def append_jsonl(path, row):
    STATE.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def rel(p):
    try:
        return str(Path(p).resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(p)


# ---------- LESSONS.md ----------
def split_row(line):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", s)]


def backticks(cell):
    return [b for b in re.findall(r"`([^`]+)`", cell) if b.strip()]


def load_lessons():
    """LESSONS.md 표를 읽는다. [{id, sigs[], cause, rule, checks[]}]"""
    if not LESSONS.exists():
        return [], ["LESSONS.md가 없다"]
    lines = LESSONS.read_text(encoding="utf-8").splitlines()
    head_i = next((i for i, l in enumerate(lines)
                   if l.strip().startswith("|") and split_row(l)[0] == "ID" and "증상" in l), None)
    if head_i is None:
        return [], ["LESSONS.md에서 '| ID | 증상 ...' 표 머리글을 찾지 못했다"]
    head = split_row(lines[head_i])
    col = {}
    for name in ("ID", "증상", "원인", "규칙", "쓰기 검사"):
        idx = next((j for j, h in enumerate(head) if h.startswith(name)), None)
        if idx is None:
            return [], [f"LESSONS.md 표 머리글에 '{name}' 칸이 없다"]
        col[name] = idx
    lessons, problems = [], []
    for i in range(head_i + 1, len(lines)):
        if not lines[i].strip().startswith("|"):
            break
        row = split_row(lines[i])
        if all(set(c) <= set("-: ") for c in row):
            continue
        row += [""] * (len(head) - len(row))
        lid = row[col["ID"]]
        checks = []
        for pat in backticks(row[col["쓰기 검사"]]):
            try:
                checks.append((pat, re.compile(pat)))
            except re.error as e:
                problems.append(f"{lid}: 쓰기 검사 정규식 오류 `{pat}`: {e}")
        sigs = backticks(row[col["증상"]])
        for s in sigs:
            if len(s) < 4:
                problems.append(f"{lid}: 증상 문구 `{s}`가 너무 짧다 (4자 이상)")
        lessons.append({"id": lid, "sigs": [s for s in sigs if len(s) >= 4],
                        "cause": row[col["원인"]], "rule": row[col["규칙"]], "checks": checks})
    return lessons, problems


def match_lessons(text, lessons):
    low = text.lower()
    hits = []
    for L in lessons:
        found = [s for s in L["sigs"] if s.lower() in low]
        if found:
            hits.append((L, found))
    return hits


def lesson_msg(hits, where):
    out = [f"[LESSONS] {where}에 기록된 교훈과 같은 증상이 있다. 고치기 전에 아래를 먼저 적용한다."]
    for L, found in hits:
        out.append(f"- {L['id']} (증상: {', '.join(found)})\n  원인: {L['cause']}\n  규칙: {L['rule']}")
    return "\n".join(out)


# ---------- 문제 폴더와 scope.md ----------
def problem_dirs():
    def mtime(p):
        n = p / "notes.md"
        return n.stat().st_mtime if n.exists() else 0
    return sorted([p for p in ROOT.iterdir()
                   if p.is_dir() and not p.name.startswith((".", "_")) and (p / "scope.md").exists()],
                  key=mtime, reverse=True)


def read_scope(d):
    fields = {}
    for line in (d / "scope.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^-\s*([^:]+?)\s*:\s*(.*)$", line)
        if m:
            fields.setdefault(m.group(1).strip(), m.group(2).strip().strip("`").strip())
    return fields


def scope_problems(d, f):
    kind = f.get("종류", "")
    need = list(REQUIRED)
    probs = []
    if "대회" in kind:
        need.append("공식 페이지 주소")
    elif "워게임" in kind:
        need.append("문제 페이지 주소")
    else:
        probs.append("종류 칸이 '대회' 또는 '워게임'이 아니다")
    probs += [f"'{k}' 칸이 비었다" for k in need if not f.get(k) and k != "종류"]
    if f.get("대상 주소 확인") and f["대상 주소 확인"] != "일치":
        probs.append("대상 주소 확인이 '일치'가 아니다")
    cap = f.get("문제 페이지 캡처 경로")
    if cap and not (d / cap).exists():
        probs.append(f"캡처 파일이 없다: {cap}")
    return probs


def hostname(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def is_local(h):
    return h in LOCAL_HOSTS or h.endswith(".localhost")


def flag_regex(fmt):
    fmt = (fmt or "").strip()
    if not fmt:
        return None
    try:
        if "{" in fmt:
            prefix = fmt.split("{", 1)[0].rstrip("\\")
            return re.compile(re.escape(prefix) + r"\{[^}\r\n]{1,300}\}")
        return re.compile(fmt)
    except re.error:
        return None


def problem_of(path):
    try:
        parts = Path(path).resolve().relative_to(ROOT.resolve()).parts
    except Exception:
        return None
    if len(parts) >= 2 and not parts[0].startswith((".", "_")) and (ROOT / parts[0] / "scope.md").exists():
        return ROOT / parts[0]
    return None


# ---------- 상태 ----------
def resolved_until():
    """이 시각 이전의 실패는 처리된 것으로 본다: LESSONS.md 수정 시각 또는 마지막 dismiss."""
    t = LESSONS.stat().st_mtime if LESSONS.exists() else 0
    for d in load_jsonl(DISMISSED):
        t = max(t, d.get("ts", 0))
    return t


def open_failures(session=None):
    until = resolved_until()
    return [f for f in load_jsonl(FAILURES)
            if not f.get("matched") and f.get("ts", 0) > until
            and (session is None or f.get("session") == session)]


# ---------- 이벤트 ----------
def ev_session(inp):
    out = ["# 웹 CTF 키트: 세션 시작 시 hook이 넣는 내용",
           "아래 LESSONS.md는 이전 문제에서 확인한 교훈이다. 이번 작업에도 그대로 적용한다."]
    out.append(LESSONS.read_text(encoding="utf-8").strip() if LESSONS.exists() else "(LESSONS.md 없음)")
    dirs = problem_dirs()
    if dirs:
        d = dirs[0]
        notes = d / "notes.md"
        if notes.exists():
            m = re.search(r"## 현재 상태\n(.*?)(?=\n## |\Z)", notes.read_text(encoding="utf-8"), re.S)
            if m:
                out.append(f"## 가장 최근 문제: {d.name}/ (notes.md 현재 상태)\n{m.group(1).strip()}")
    pend = open_failures()
    if pend:
        out.append(f"## LESSONS에 아직 반영 안 된 실패 {len(pend)}건\n"
                   + "\n".join(f"- {p.get('cmd', '')[:120]} → {p.get('error', '')[:160]}" for p in pend[-5:]))
    print("\n\n".join(out))
    return 0


def ev_pre_bash(inp):
    cmd = (inp.get("tool_input") or {}).get("command", "") or ""

    m = GIT_WRITE_RE.search(cmd)
    if m:
        return block([f"[CLAUDE.md 9번] git {m.group(1)}는 하지 않는다. 커밋·푸시는 사람이 한다. "
                      "필요한 파일 목록과 커밋 메시지만 사람에게 알려라."])

    if not NET_TOOL_RE.search(cmd):
        return 0
    hosts = {hostname(u) for u in URL_RE.findall(cmd)}
    hosts |= {h.lower() for h in NC_RE.findall(cmd)}
    hosts |= {h.lower() for h in CONNECT_RE.findall(cmd)}
    hosts = {h for h in hosts if h and not is_local(h)}
    if not hosts:
        return 0

    allowed, incomplete = set(), {}
    for d in problem_dirs():
        f = read_scope(d)
        target = hostname(f.get("대상 주소", ""))
        if not target:
            continue
        probs = scope_problems(d, f)
        if probs:
            incomplete[target] = (d.name, probs)
            continue
        allowed.add(target)
        recv = f.get("수신 주소", "")
        if recv and recv != "-":
            allowed.add(hostname(recv) or recv.lower())
    if ALLOWED_HOSTS_FILE.exists():
        for line in ALLOWED_HOSTS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                allowed.add(line)

    bad = []
    for h in sorted(hosts - allowed):
        if h in incomplete:
            name, probs = incomplete[h]
            bad.append(f"- {h}: {name}/scope.md가 완성되지 않았다 ({'; '.join(probs)})")
        else:
            bad.append(f"- {h}: 어느 문제의 scope.md에도 대상·수신 주소로 없다")
    if bad:
        return block(["[CLAUDE.md 2번] 범위 밖 호스트라 요청하지 않는다.", "\n".join(bad),
                      "받은 파일 분석과 로컬 재현만 하고, 빈 칸이나 주소를 사람에게 알려라. "
                      "사람이 허락한 호스트는 사람이 .claude/allowed_hosts.txt에 적는다."])
    return 0


def ev_pre_edit(inp):
    ti = inp.get("tool_input") or {}
    path = ti.get("file_path") or ti.get("notebook_path") or ""
    r = rel(path)
    if any(r == p.rstrip("/") or r.startswith(p) for p in PROTECTED):
        return block([f"[hook] {r}는 고치지 않는다. 강제 장치를 바꾸는 일은 사람이 한다. "
                      "hook 때문에 막혔다면 막힌 이유를 사람에게 알려라."])
    return 0


def bump_counter(session):
    STATE.mkdir(parents=True, exist_ok=True)
    c = load_json(COUNTER, {})
    if c.get("session") != session:
        c = {"session": session, "n": 0}
    c["n"] += 1
    COUNTER.write_text(json.dumps(c), encoding="utf-8")
    return c["n"]


def flag_notes(text, cmd):
    seen, out = set(), []
    for d in problem_dirs():
        fmt = read_scope(d).get("플래그 형식", "")
        fr = flag_regex(fmt)
        if not fr:
            continue
        for m in fr.findall(text):
            inner = m.split("{", 1)[-1].rstrip("}")
            if m in seen or m == fmt or inner.strip() in {"...", ".*", "…", ""}:
                continue
            seen.add(m)
            note = "명령에 내가 넣은 문자열이 되돌아온 것일 수 있다" if m in cmd else "대상 응답인지 out/ 원문으로 확인"
            out.append(f"- {m} ({d.name} 형식, {note})")
    if not out:
        return ""
    return ("[CLAUDE.md 1번] 플래그 후보가 나왔다. 여기서 멈추고 요청과 응답 원문(out/ 파일)을 함께 사람에게 보고한다. "
            "로컬 재현의 가짜 플래그와 구분한다.\n" + "\n".join(out))


def write_checks(path, lessons):
    p = Path(path)
    d = problem_of(p)
    if d is None or p.suffix.lower() not in WRITE_CHECK_SUFFIXES or not p.exists():
        return ""
    sub = p.resolve().relative_to(d.resolve()).parts
    if sub and sub[0] in ("out", "src"):
        return ""
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for L in lessons:
        for pat, rx in L["checks"]:
            nums = [str(i + 1) for i, l in enumerate(lines) if rx.search(l)]
            if nums:
                out.append(f"- {L['id']}: `{pat}`가 {rel(p)} {', '.join(nums[:10])}줄에 있다\n"
                           f"  원인: {L['cause']}\n  규칙: {L['rule']}")
    if not out:
        return ""
    return ("[LESSONS 쓰기 검사] 방금 쓴 파일에 지난 실패와 같은 모양이 있다. "
            "실행 환경에서 문제가 되는지 확인하고 필요하면 고친다.\n" + "\n".join(out))


def secret_check(path):
    p = Path(path)
    if not p.exists() or p.suffix.lower() != ".md":
        return ""
    if p.name != "writeup.md" and "blog" not in str(p).lower():
        return ""
    text = p.read_text(encoding="utf-8", errors="replace")
    hits = []
    for name, rx in SECRET_RES:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"- {line}줄 {name}: {m.group(0)[:40]}…")
    if not hits:
        return ""
    return (f"[CLAUDE.md 8번] {rel(p)}에 세션 쿠키·토큰 값이 보인다. 값을 `<가림>`이나 `***`로 가린다.\n"
            + "\n".join(hits[:10]))


def ev_post(inp, lessons):
    tool = inp.get("tool_name", "")
    ti = inp.get("tool_input") or {}
    notes, blocks = [], []

    n = bump_counter(inp.get("session_id", ""))
    if n % NOTE_EVERY == 0:
        notes.append(f"[CLAUDE.md 5번] 도구 호출 {n}번째다. notes.md를 정리하고 사람에게 진행 상황을 알린다.")

    if tool == "Bash":
        cmd = ti.get("command", "") or ""
        text = "\n".join(strings_in(inp.get("tool_response")))
        if "LESSONS.md" not in cmd:
            hits = match_lessons(text, lessons)
            if hits:
                notes.append(lesson_msg(hits, "방금 출력"))
        fn = flag_notes(text, cmd)
        if fn:
            notes.append(fn)

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        p = Path(path)
        if p.name == "hypotheses.md" and (p.parent / "check_hypotheses.py").exists():
            r = subprocess.run([sys.executable, str(p.parent / "check_hypotheses.py"), str(p.parent)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=30)
            if r.returncode != 0:
                blocks.append("[CLAUDE.md 4번] check_hypotheses.py가 통과하지 않았다. 고친 뒤 다음 단계로 간다.\n"
                              + (r.stdout + r.stderr).strip())
        if p.name == "LESSONS.md":
            _, probs = load_lessons()
            if probs:
                blocks.append("[LESSONS.md 형식] " + "; ".join(probs))
        sc = secret_check(path)
        if sc:
            blocks.append(sc)
        wc = write_checks(path, lessons)
        if wc:
            notes.append(wc)

    if blocks:
        return block(blocks + notes)
    return context("PostToolUse", notes)


def ev_post_fail(inp, lessons):
    ti = inp.get("tool_input") or {}
    cmd = ti.get("command", "") or ""
    text = "\n".join(strings_in(inp, skip={"session_id", "transcript_path", "cwd", "hook_event_name",
                                           "tool_input", "tool_name", "tool_use_id", "permission_mode"}))
    code = EXIT_RE.search(text)
    # grep·diff·test의 종료 코드 1은 "못 찾음/다름"이라는 정상 결과라 실패로 세지 않는다.
    if code and code.group(1) == "1" and NOMATCH_CMD_RE.search(cmd):
        return 0
    hits = match_lessons(text, lessons) if "LESSONS.md" not in cmd else []
    append_jsonl(FAILURES, {"ts": time.time(), "session": inp.get("session_id", ""),
                            "cmd": cmd[:300], "error": text.strip()[:400],
                            "matched": [L["id"] for L, _ in hits]})
    if hits:
        return context("PostToolUseFailure", [lesson_msg(hits, "이 실패")])
    return context("PostToolUseFailure", [
        "[LESSONS] LESSONS.md에 없는 실패다. 바로 다시 시도하지 말고 원인을 먼저 확인한다.\n"
        "- 원인이 확인되면 LESSONS.md 표에 한 줄 추가한다(증상 칸에는 오류 문구를 백틱으로 그대로).\n"
        "- 오타 같은 일회성 실수면: python3 .claude/hooks/kit_hooks.py dismiss \"이유\""])


def ev_stop(inp):
    if inp.get("stop_hook_active"):
        return 0
    pend = open_failures(inp.get("session_id"))
    if not pend:
        return 0
    lines = "\n".join(f"- {p.get('cmd', '')[:120]} → {p.get('error', '')[:160]}" for p in pend[-5:])
    print(json.dumps({"decision": "block", "reason":
        f"LESSONS.md에 반영 안 된 실패가 {len(pend)}건 있다.\n{lines}\n"
        "원인이 확인된 것은 LESSONS.md 표에 행을 추가한다(증상, 원인, 규칙, 쓰기 검사). "
        "일회성 실수면 python3 .claude/hooks/kit_hooks.py dismiss \"이유\"를 실행한다. "
        "원인을 아직 모르면 notes.md에 '미해결 실패'로 적고 dismiss한 뒤 사람에게 알린다."},
        ensure_ascii=False))
    return 0


def cmd_dismiss(reason):
    if not reason.strip():
        print('사용법: python3 .claude/hooks/kit_hooks.py dismiss "이유"', file=sys.stderr)
        return 1
    n = len(open_failures())
    append_jsonl(DISMISSED, {"ts": time.time(), "reason": reason.strip(), "count": n})
    print(f"정리함: 실패 {n}건 (이유: {reason.strip()})")
    return 0


def cmd_check():
    lessons, probs = load_lessons()
    for p in probs:
        print(p)
    print(f"교훈 {len(lessons)}개, 증상 문구 {sum(len(L['sigs']) for L in lessons)}개, "
          f"쓰기 검사 {sum(len(L['checks']) for L in lessons)}개, 문제 {len(probs)}개")
    return 1 if probs else 0


def main():
    ev = sys.argv[1] if len(sys.argv) > 1 else ""
    if ev == "dismiss":
        return cmd_dismiss(" ".join(sys.argv[2:]))
    if ev == "check":
        return cmd_check()
    inp = read_input()
    if ev == "session":
        return ev_session(inp)
    if ev == "pre-bash":
        return ev_pre_bash(inp)
    if ev == "pre-edit":
        return ev_pre_edit(inp)
    if ev == "stop":
        return ev_stop(inp)
    lessons, _ = load_lessons()
    if ev == "post":
        return ev_post(inp, lessons)
    if ev == "post-fail":
        return ev_post_fail(inp, lessons)
    print(f"알 수 없는 이벤트: {ev}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # hook 오류로 작업 전체가 멈추지 않게 통과시킨다 (L04)
        print(f"[kit_hooks] hook 내부 오류로 검사를 건너뛴다: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
