# 웹 CTF 키트 (v4)

Claude Code로 웹 CTF·워게임 문제를 풀 때 쓰는 규칙과 템플릿이다.
에이전트가 범위를 지키고, 근거 있는 가설만 하나씩 시험하고, 진행을 파일에 남기게 만든다.

## 폴더 구조

```
CLAUDE.md                        항상 지키는 규칙 (범위, 기록, 가설 관리, 공유 인프라, 계정·토큰)
LESSONS.md                       문제가 바뀌어도 이어지는 교훈 표 (hook이 매 세션 자동으로 넣는다)
.claude/skills/web-ctf/SKILL.md  푸는 순서 (/web-ctf)
.claude/settings.json            hook 등록
.claude/hooks/kit_hooks.py       hook 본체 (규칙 강제, 교훈 대조)
.claude/allowed_hosts.txt        사람이 허락한 추가 호스트 (문서 사이트 등)
.claude/state/                   실패 기록·카운터 (저장소에 안 올라감)
new.sh                           새 문제 폴더 만들기
_template/
  scope.md              범위 확인: 대회/워게임, 문제 페이지, 대상 주소, 규칙 원문
  recon.md              정찰: 문서 요약, 경로, 인증, 쿠키·토큰, 플래그 위치, 신뢰 경계
  hypotheses.md         가설 표 + 아이디어 목록
  attempt.md            지금 하는 시험 하나 (예상 결과를 먼저 적는다)
  notes.md              현재 상태, 확인된 사실, 진행 기록
  writeup.md            라이트업
  solve.py              풀이 스크립트 (응답 원문 저장, 플래그 자동 감지, 범위 검사)
  check_hypotheses.py   가설 표 검사
  src/                  받은 파일 (소스, Burp 기록, 문제 페이지 캡처)
  out/                  서버 응답 원문, grep 결과
```

문제 폴더는 저장소에 올라가지 않는다(`.gitignore`가 허용한 파일만 올린다).

## 쓰는 법

```bash
./new.sh 문제이름 http://대상 'flag{...}'
```

1. `문제이름/scope.md` 나머지 칸을 채운다. 문제 페이지 캡처는 `src/`에 넣는다.
2. 받은 소스나 Burp 기록을 `문제이름/src/`에 넣는다.
3. 이 폴더에서 Claude Code를 열고 `/web-ctf 문제이름`으로 시작한다.
4. `solve.py`는 `requests`가 있는 파이썬으로 실행한다: `python3 solve.py http://대상`

## 푸는 순서

0. 범위 확인: `scope.md`가 비었거나 대상 주소가 문제 페이지와 다르면 대상에 요청하지 않는다.
1. 갈래 나누기
   - **A. 소스 있음**: 구조 파악 → 플래그 역추적 → 입력 지점 표 → 위험 함수 grep → 인증·권한 → 쿠키·토큰 → 해석 차이 → Docker 로컬 재현
   - **B. 블랙박스**: 문서 먼저 → Burp 기록으로 기능 지도 → 서버 종류 → 쿠키·토큰 → 플래그 위치 추정 → 신뢰 경계
2. `hypotheses.md`에 가설 정리 (가능성 높고, 확인이 싸고, 플래그에 가까운 순)
3. `attempt.md`로 하나씩 시험
4. 실행 능력을 얻으면 환경 정찰 후 바로 플래그를 읽는다
5. `writeup.md`, `solve.py` 정리

## 가설 관리 규칙

- 근거(`src/파일:줄` 또는 `out/` 파일)가 없으면 표가 아니라 "아이디어"에 둔다.
- 시험 전에 참·거짓일 때 예상 결과를 적고, 정상값 대조 요청을 보낸다.
- 확인·기각에는 `out/` 또는 `src/` 증거가 있어야 한다. 확인 전에 다른 설명 하나를 배제한다.
- 가설 하나에 시도 2번까지(넘으면 보류). 3번 연속 기각이면 정찰로 돌아간다.
- 상태를 바꾸면 `python3 check_hypotheses.py`가 통과해야 다음으로 간다.

## hook이 강제하는 것

| 시점 | 하는 일 | 근거 |
|---|---|---|
| 세션 시작·`/clear`·대화 요약 뒤 | `LESSONS.md`, 가장 최근 문제의 `notes.md` 현재 상태, 정리 안 된 실패를 넣는다 | 대화 요약으로 교훈이 빠지는 것 방지 |
| Bash 실행 전 | `git add/commit/push` 차단 | CLAUDE.md 9번 |
| Bash 실행 전 | 네트워크 도구(curl, wget, nc, sqlmap 등)가 완성된 `scope.md`의 대상·수신 주소, 로컬, `allowed_hosts.txt`가 아닌 호스트로 가면 차단 | CLAUDE.md 2번 |
| 파일 수정 전 | `.claude/hooks/`, `.claude/settings.json`, `.claude/allowed_hosts.txt` 수정 차단 | 강제 장치를 에이전트가 끄지 못하게 |
| Bash 실행 후 | 출력에 `LESSONS.md` 증상 문구가 있으면 그 교훈을 알려준다 | 원격 로그(CI job 로그 등)는 명령이 성공해도 실패 내용을 담고 있다 |
| Bash 실행 후 | 출력에 플래그 형식이 나오면 멈추고 보고하라고 알린다 (명령에 넣은 문자열이면 반사 가능성 표시) | CLAUDE.md 1번 |
| 파일 수정 후 | `hypotheses.md`를 고치면 `check_hypotheses.py`를 자동 실행, 실패하면 되돌려 보낸다 | CLAUDE.md 4번 |
| 파일 수정 후 | `writeup.md`, 블로그 글에 JWT·쿠키·토큰 값이 있으면 가리라고 되돌려 보낸다 | CLAUDE.md 8번 |
| 파일 수정 후 | 문제 폴더의 `.yml`·`.sh` 등이 `LESSONS.md` 쓰기 검사 정규식에 걸리면 경고 | 같은 실수 반복 방지 |
| 도구 호출 30번마다 | `notes.md` 정리와 보고를 알린다 | CLAUDE.md 5번 |
| Bash 실패 후 | 교훈과 맞으면 알려주고, 처음 보는 실패는 `.claude/state/`에 기록 | 원인 기록 강제 |
| 응답을 끝내려 할 때 | 기록 안 된 새 실패가 있으면 한 번 멈추고 `LESSONS.md`에 적거나 dismiss하라고 한다 | 원인 기록 강제 |

`python3 .claude/hooks/kit_hooks.py check`로 `LESSONS.md` 형식을 검사한다. hook은 `/hooks`로 등록됐는지 확인한다.

## 한계

- hook은 코드로 확인할 수 있는 것만 강제한다. 가설의 질, 다른 설명 배제, 시도 횟수 같은 판단은 여전히 에이전트가 지키는 약속이라 사람이 지켜본다.
- 범위 검사는 명령 문자열에 보이는 주소만 본다. 스크립트 파일 안의 주소는 `solve.py`의 범위 검사가 맡는다.
- hook 자체에 오류가 나면 작업을 막지 않고 통과시킨다(hook이 깨져 모든 작업이 멈추는 것보다 낫다). 오류 메시지가 보이면 사람이 고친다.
- CAPTCHA, 봇 차단, 플랫폼 로그인 같은 보호 장치에 막히면 사람이 진행한다.
- 대회 플랫폼 계정, 로그인, 플래그 제출은 사람이 한다.
