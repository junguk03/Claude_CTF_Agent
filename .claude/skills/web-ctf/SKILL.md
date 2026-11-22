---
name: web-ctf
description: 웹 CTF·워게임 문제를 풀 때 쓴다. 범위 확인, 소스 유무에 따른 갈래(A 소스 분석 / B 블랙박스 정찰), 가설 표 정리, attempt 순환, 실행 능력 획득 후 정찰, 출력 채널, 추출 효율, 마무리 순서.
---

# 웹 CTF 푸는 순서

규칙은 `CLAUDE.md`가 우선한다. 각 단계 결과는 문제 폴더 파일에 바로 적는다.
명령은 문제 폴더 안에서 실행한다. 긴 출력은 `out/`에 저장하고 grep으로 본다.

## 0. 범위 확인
- `scope.md` 필수 칸과 "대상 주소 확인: 일치"를 확인한다 (CLAUDE.md 2번).
- 비었거나 대상 주소가 문제 페이지와 다르면 대상 요청 없이 받은 파일 분석과 로컬 재현만 하고 사람에게 알린다.
- `notes.md` "현재 상태"를 읽고 이어서 시작한다.

## 1. 갈래 나누기
```bash
find src -type f ! -name .keep | head -100
```
- `src/`에 소스(코드, Dockerfile, docker-compose.yml)가 있으면 **A**, 없으면 **B**.
- Burp 기록만 있으면 B다. `notes.md` "갈래"에 적는다.

---

## A. 소스 있음

### A1. 구조 파악
- Dockerfile, docker-compose.yml, 진입점, 라우트 정의, 의존성 파일(package.json, requirements.txt, composer.json, pom.xml, go.mod)과 버전.
- 프록시(nginx 등)와 앱이 나뉘어 있으면 둘 다 본다.
- `recon.md` "구성 요소와 경로"에 적는다.

### A2. 플래그 역추적
플래그를 읽는 코드부터 거꾸로 간다.
```bash
grep -rniE 'flag' src/ > out/grep_flag.txt
find src -iname 'Dockerfile*' -o -iname 'docker-compose*' -o -iname '*.sh' | xargs grep -niE 'flag|COPY|ENV|RUN|chmod|chown|USER|ENTRYPOINT|CMD'
```
- 플래그가 어디 있나: 파일(경로, 권한, 소유자), 환경 변수, DB 시드, 관리자 봇 쿠키, `/readflag` 같은 실행 파일(→ 명령 실행이 필요).
- 그 값을 읽거나 돌려주는 코드(`파일:줄`) → 그 코드에 닿는 경로 → 필요한 조건(권한, 세션 값, 내부 요청) → 그 조건을 만드는 입력.
- `recon.md` "플래그 위치 추정"과 "데이터 흐름"에 적는다.

### A3. 입력 지점 표
`recon.md` "구성 요소와 경로" 표를 채운다: 경로 | 메서드 | 입력 위치(쿼리·본문·쿠키·헤더·파일·경로) | 파라미터 | 인증 | 처리 위치(`파일:줄`).

### A4. 위험 함수 grep
언어에 맞는 것만 돌린다. 결과는 `out/grep_*.txt`.
```bash
# PHP
grep -rnE --include='*.php' 'eval\(|assert\(|system\(|exec\(|shell_exec|passthru|popen|proc_open|`|include|require|file_get_contents|file_put_contents|fopen|unserialize|preg_replace|extract\(|parse_str|\$\$|move_uploaded_file|simplexml_load|loadXML|->query\(|mysqli_query|==' src/ > out/grep_php.txt
# Node
grep -rnE --include='*.js' --include='*.ts' --include='*.mjs' 'eval\(|new Function|child_process|exec\(|execSync|spawn|vm\.|res\.render|render\(|innerHTML|dangerouslySetInnerHTML|merge\(|extend\(|__proto__|constructor|\.query\(|\$where|readFile|sendFile|path\.join|res\.redirect|serialize|yaml\.load|fetch\(|axios' src/ --exclude-dir=node_modules > out/grep_node.txt
# Python
grep -rnE --include='*.py' 'eval\(|exec\(|os\.system|subprocess|popen|pickle|yaml\.load|render_template_string|Template\(|\.format\(|send_file|send_from_directory|open\(|execute\(|raw\(|redirect\(|requests\.|urllib|secret_key|SECRET' src/ > out/grep_py.txt
# Java
grep -rnE --include='*.java' --include='*.jsp' --include='*.xml' 'Runtime\.getRuntime|ProcessBuilder|ObjectInputStream|readObject|XMLDecoder|XStream|enableDefaultTyping|@JsonTypeInfo|ScriptEngine|parseExpression|SpEL|Ognl|lookup\(|createQuery|createStatement|executeQuery|DocumentBuilder|SAXParser|new File\(|getResource|Paths\.get|sendRedirect' src/ > out/grep_java.txt
```
나온 줄마다 "사용자 입력이 여기까지 오는가"를 A3 표와 맞춰 본다.

### A5. 인증·권한
- 로그인·가입·비밀번호 재설정, 세션 생성 위치, 권한 검사 미들웨어와 그것이 빠진 라우트.
- 비교 방식(`==` 타입 저글링, `strcmp`에 배열, 대소문자, 앞뒤 공백), 하드코딩된 비밀키·기본 계정.

### A6. 쿠키·토큰 분석
- 세션 서명 키의 출처(.env, 기본값, 짧은 랜덤), 세션 저장 방식(클라이언트 서명 쿠키인지 서버 저장인지).
- JWT 라이브러리 설정: 허용 알고리즘(none, HS/RS 혼동), 키 하드코딩, `kid`·`jku` 처리, 만료 검사.
- 토큰 생성 방식: 순번, 시각 기반, 시드 고정 난수, uuid1, 짧은 길이.
- CSRF 토큰과 OAuth state를 실제로 검증하는 코드가 있는지.
- `recon.md` "쿠키·토큰"에 적는다.

### A7. 해석 차이
검사하는 쪽과 쓰는 쪽이 같은 값을 다르게 읽는 곳을 찾는다.
- URL 파서 두 개(검사용 `urlparse`와 실제 요청 라이브러리), 경로 정규화(`..`, `%2e`, `//`, `;`, 역슬래시), 프록시와 앱의 경로 규칙.
- 중복 파라미터·중복 JSON 키, Content-Type에 따라 다른 본문 파서, 배열·객체가 문자열 자리에 들어오는 경우.
- 대소문자·유니코드 정규화, 정규식 앵커(`^`·`$`·여러 줄), 길이 제한 뒤 자르기, 디코딩 횟수(이중 인코딩).

### A8. 로컬 재현
대상에 보내기 전에 Docker로 로컬에서 먼저 성공시킨다.
```bash
cd src && docker compose up -d --build   # 또는 docker build / docker run
```
- 플래그 자리에 가짜 값을 넣고 로컬에서 `python3 solve.py http://localhost:포트`로 확인한다.
- 로컬 플래그는 가짜다. 성공 판정은 대상 응답으로만 한다 (CLAUDE.md 1번).

---

## B. 블랙박스 (소스 없음)
플래그 역추적 대신 "플래그 위치 추정"을 한다.

### B1. 문서 먼저
- 문서·정책·보안·도움말·소개·API 문서 페이지 전문을 먼저 읽고 원문을 `out/`에 저장한다.
- `recon.md` "문서 요약"에 핵심 문장을 인용한다. 설계 설명에 취약점이 그대로 적혀 있는 경우가 많다(예: "관리자가 신고된 링크를 확인합니다", "캐시합니다", "내부 서비스가 ...를 믿습니다").

### B2. Burp 기록에서 기능 지도
- `src/` 안의 파일을 이름과 상관없이 찾는다. base64면 푼다.
```bash
grep -rlE '<items burpVersion|<item>' src/ ; file src/*
```
- 대상 호스트 항목만 뽑는다(다른 호스트는 무시하고 파일에 적지 않는다, CLAUDE.md 8번).
```bash
python3 - src/파일 대상호스트 <<'PY'
import base64, sys, xml.etree.ElementTree as ET
path, host = sys.argv[1], sys.argv[2]
seen, dump = set(), open("out/burp_dump.txt", "w", encoding="utf-8")
for it in ET.parse(path).getroot().iter("item"):
    if (it.findtext("host") or "") != host:
        continue
    def body(tag):
        e = it.find(tag)
        if e is None or e.text is None: return ""
        raw = base64.b64decode(e.text) if e.get("base64") == "true" else e.text.encode()
        return raw.decode("utf-8", "replace")
    m, p, s = it.findtext("method"), it.findtext("path"), it.findtext("status")
    seen.add(f"{m} {p.split('?')[0]} {s}")
    dump.write(f"===== {m} {p} -> {s}\n{body('request')}\n----- response\n{body('response')}\n\n")
open("out/burp_endpoints.txt", "w").write("\n".join(sorted(seen)) + "\n")
print(len(seen), "endpoints")
PY
```
- `out/burp_endpoints.txt`로 `recon.md` "구성 요소와 경로" 표와 "인증 흐름"을 채운다. 기록 속 쿠키·토큰 값은 구조 파악에만 쓴다.

### B3. 서버 종류 추정
- 응답 헤더: `Server`, `X-Powered-By`, `Via`, `X-Cache`, CSP.
- 쿠키 이름: `PHPSESSID`(PHP), `connect.sid`(Express), `JSESSIONID`(Java), `session`(Flask), `sessionid`·`csrftoken`(Django), `laravel_session`, `_..._session`(Rails).
- 오류 페이지: 없는 경로, 잘못된 메서드, 깨진 JSON을 각 한 번 보내 본다(Werkzeug, `Cannot GET`(Express), Whitelabel(Spring), nginx·Apache 기본 페이지).
- 근거 `out/` 파일과 함께 `recon.md`에 적는다.

### B4. 쿠키·토큰 분석
- `recon.md` "쿠키·토큰" 칸에 이름, 발급 위치, 속성(HttpOnly, SameSite, Secure), 형식을 적는다.
- JWT면 디코딩해서 알고리즘과 내용(사용자 ID, 권한, 만료)을 적는다. 서명 키가 약하거나 검증이 빠졌을 가능성은 가설로 올린다.
```bash
python3 -c 'import sys,base64,json;[print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))) for p in sys.argv[1].split(".")[:2]]' '<JWT>'
```
- Flask 세션 쿠키는 앞부분이 base64 JSON이다(`.`으로 시작하면 zlib 압축).
- 값이 예측 가능한지(순번, 시각 기반, 짧은 길이): 인스턴스 안에서 계정이나 토큰을 두세 번 새로 받아 비교하는 가설을 만든다.
- CSRF 토큰과 OAuth state를 실제로 검증하는지(빼기, 다른 값, 다른 세션 값) 확인하는 가설을 만든다.

### B5. 플래그 위치 추정
- 문제 설명, 이름(문제·레포·계정·경로 이름), 문서 문구에서 플래그가 있을 곳을 적는다(관리자 페이지, 다른 사용자 데이터, 봇 쿠키, 서버 파일, 비공개 저장소 등).
- `recon.md` "플래그 위치 추정"에 근거와 함께 적는다.

### B6. 신뢰 경계
- 누가 무엇을 검사 없이 믿는지: 사용자 입력, 공유 자원(업로드 파일, 공용 저장소), 캐시, 다른 서비스·내부 API, 프록시 헤더(`X-Forwarded-For`, `Host`).
- `recon.md` "신뢰 경계" 표에 적는다.

---

## 2. 가설 정리 (hypotheses.md)
- 근거(`src/파일:줄` 또는 `out/` 파일)가 있는 것만 표에 넣는다. 나머지는 "아이디어".
- 순위: 가능성 높고, 확인이 싸고, 플래그에 가까운 순.
  - 가능성: 상/중/하. 비용: 낮음/중간/높음(요청 수·시간). 거리: 성공하면 플래그까지 남은 단계 수(1 = 바로 플래그).
- 예: `| H1 | /download의 name 경로 탐색 | src/app.py:42 | 상 | 낮음 | 1 | 대기 | |`
- 쓰고 나면 `python3 check_hypotheses.py`.

## 3. 하나씩 수행 (attempt.md)
CLAUDE.md 4번·5번대로 돈다.
1. 가장 높은 가설 하나를 `attempt.md`에: 목표, 최소 확인 방법, 참일 때 예상, 거짓일 때 예상.
2. 대조 요청(정상값) → 시험 요청. 둘 다 `out/`에 남는다(`solve.py`).
3. 다른 설명 하나와 배제 이유를 적고 판정.
4. `hypotheses.md` 상태·증거 → `notes.md` 진행 기록 → `python3 check_hypotheses.py` → `attempt.md` 덮어쓰기.
- 시도 2번 넘으면 보류. 3번 연속 기각이면 B1·A2로 돌아간다. attempt 10번마다 `hypotheses.md`만 다시 읽고 약한 행을 검토한다.

## 4. 실행 능력을 얻으면
먼저 실행 환경을 정찰한다. 읽기 명령만 쓴다.
```sh
id; hostname; pwd; ls -la / /app ~ 2>/dev/null
env; cat /proc/self/environ 2>/dev/null | tr '\0' '\n'   # 플래그가 환경 변수에 있는지
mount; df -h                                              # 공유 볼륨: 다른 참가자와 같이 쓰는지
cat /proc/1/cmdline | tr '\0' ' '; ls -la /docker-entrypoint* /entrypoint* /start* 2>/dev/null  # 시작 스크립트
which python3 curl wget nc bash; sudo -l 2>/dev/null     # 쓸 수 있는 명령
find / -maxdepth 4 -iname '*flag*' 2>/dev/null; ls -la /readflag* 2>/dev/null
```
- 결과는 `notes.md` "확보한 능력"과 "실행 한도"에 적고, 바로 플래그를 읽는다.
- 공유 볼륨에 파일을 만들었으면 `notes.md` "바꾼 공유 자원"에 적고 끝나면 지운다 (CLAUDE.md 6번).

## 5. 출력 채널
결과가 응답에 안 보이면 받을 곳을 미리 정하고, 무해한 고정 문자열로 먼저 채널을 시험한다.
1. 같은 응답 안: 오류 메시지, 반사되는 값, 응답 헤더.
2. 내가 볼 수 있는 다른 화면: 내 프로필·게시물, 로그·상태 페이지, 정적 파일 경로에 쓰기.
3. `scope.md`의 수신 주소(봇이나 서버가 밖으로 요청할 수 있을 때). 다른 수신 주소는 쓰지 않는다.
4. 부채널: 참/거짓 응답 차이, 길이, 상태 코드. 시간 지연은 마지막 수단이다.

## 6. 추출 효율
블라인드·부채널 추출은 시작 전에 예상 요청 수와 시간을 말하고(CLAUDE.md 7번), 아래를 적용한 전후를 비교한다.
- 아는 부분 빼기: 플래그 형식 접두사·`}`는 뽑지 않는다. 길이를 먼저 잰다. 문자 집합을 줄인다(hex면 16자).
- 이진 탐색: 한 글자에 `>` 비교 7번(ASCII). 글자마다 순차 대입하지 않는다.
- 한 번에 여러 값: 여러 행을 이어 붙여 한 번에, 한 요청에서 여러 비트를 서로 다른 응답(상태 코드·길이·오류)으로 구분.
- 기다리는 시간 줄이기: 시간 기반 대신 오류·불리언 기반, 지연은 짧게, 세션 재사용(keep-alive).
- 결과는 한 글자씩 `out/` 파일에 추가하고, 다시 시작하면 그 길이부터 잇는다.

## 7. 마무리
- 플래그 후보: 멈추고 요청과 응답 원문(`out/` 파일)을 함께 보고한다.
- `solve.py`: 새 세션에서 로그인부터 플래그까지 한 번에 도는지 확인한다(Burp 값에 기대지 않는다).
- `writeup.md`: 범위 근거, 정찰, 가설 흐름(기각 포함), 원인, 풀이, 패치 방법, 시행착오. 근거는 `out/`·`notes.md`에서 가져오고 세션 쿠키·토큰 값은 가린다.
- 바꾼 공유 자원을 되돌렸는지 `notes.md`로 확인한다.
