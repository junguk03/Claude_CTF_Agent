#!/usr/bin/env python3
"""hypotheses.md 표를 검사한다.

사용법: python3 check_hypotheses.py [문제폴더]   (기본: 이 파일이 있는 폴더)

잡는 것:
  (1) 근거 칸이 빈 행
  (2) 상태가 확인·기각인데 증거 칸에 out/ 또는 src/ 경로가 없는 행
  (3) 근거·증거 칸의 out/·src/ 경로가 실제로 없는 행
  (+) 상태 값이 정해진 것(대기/시험중/확인/기각/보류)이 아닌 행
문제가 있으면 종료 코드 1, 없으면 0.
"""
import re
import sys
from pathlib import Path

NEED_COLS = ["ID", "가설", "근거", "상태", "증거"]
STATES = {"대기", "시험중", "확인", "기각", "보류"}
DONE = {"확인", "기각"}
EMPTY = {"", "-", "—", "없음", "?"}
PATH_RE = re.compile(r"(?<![\w/.])((?:out|src)/[^\s,;|`'\"()\[\]<>]+)")


def cells(line):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def clean_path(p):
    p = p.rstrip(".:")
    p = re.sub(r"#L?\d+(-L?\d+)?$", "", p)          # src/app.py#L42
    p = re.sub(r":\d+(?:[-~,]\d+)*$", "", p)          # src/app.py:42 / :42-50
    return p


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    hyp = base / "hypotheses.md"
    if not hyp.exists():
        print(f"없음: {hyp}")
        return 1
    lines = hyp.read_text(encoding="utf-8").splitlines()

    hi = next((i for i, l in enumerate(lines)
               if l.strip().startswith("|") and cells(l)[0] == "ID" and "상태" in cells(l)), None)
    if hi is None:
        print("hypotheses.md에서 '| ID | ... | 상태 | ...' 표 머리글을 찾지 못했다.")
        return 1
    head = cells(lines[hi])
    missing = [c for c in NEED_COLS if c not in head]
    if missing:
        print(f"표 머리글에 칸이 없다: {', '.join(missing)}")
        return 1
    col = {name: head.index(name) for name in head}

    problems, rows = [], 0
    for i in range(hi + 1, len(lines)):
        line = lines[i]
        if not line.strip().startswith("|"):
            break
        row = cells(line)
        if all(set(c) <= set("-: ") for c in row):     # 구분선
            continue
        if all(c in EMPTY for c in row):               # 빈 행
            continue
        rows += 1
        row += [""] * (len(head) - len(row))
        get = lambda name: row[col[name]]
        rid = get("ID") or f"(ID 없음)"
        where = f"{i + 1}줄 {rid}"
        state = get("상태")

        if len(row) > len(head):
            problems.append(f"{where}: 칸 수가 머리글보다 많다 (칸 안에 '|'를 썼는지 확인)")
        if get("근거") in EMPTY:
            problems.append(f"{where}: 근거 칸이 비었다 → '아이디어' 목록으로 옮긴다")
        if state not in STATES:
            problems.append(f"{where}: 상태 '{state}'는 정해진 값이 아니다 ({'/'.join(sorted(STATES))})")
        ev_paths = PATH_RE.findall(get("증거"))
        if state in DONE and not ev_paths:
            problems.append(f"{where}: 상태가 {state}인데 증거 칸에 out/ 또는 src/ 경로가 없다")
        for name in ("근거", "증거"):
            for p in PATH_RE.findall(get(name)):
                cp = clean_path(p)
                if not (base / cp).exists():
                    problems.append(f"{where}: {name} 칸의 파일이 없다: {cp}")

    for p in problems:
        print(p)
    print(f"검사 {rows}행, 문제 {len(problems)}개")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
