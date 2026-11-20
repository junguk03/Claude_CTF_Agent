---
name: web-ctf
description: 웹 CTF·워게임 문제를 분석할 때 쓴다. 구조 파악, 플래그 역추적, 입력 지점 표, 위험 함수 찾기, 해석 차이 확인, 후보 순위, 최소 PoC, 막혔을 때 정리 순서.
---

# 웹 CTF 분석 절차

먼저 문제 폴더의 `notes.md`(대상 주소, 플래그 형식)를 읽는다. 단계마다 결과를 `notes.md`에 짧게 적는다. 목표는 플래그다. 완벽한 분석이 아니라 플래그까지 가장 빠른 길을 찾는다.

## 1. 구조 파악
```bash
find src -type f -not -path '*/node_modules/*' -not -path '*/.git/*' | head -200
cat src/Dockerfile src/docker-compose.yml src/compose.yml 2>/dev/null
```
- 언어·프레임워크·버전, 서비스 구성(웹, DB, 관리자 봇, 프록시), 포트를 정리한다.

## 2. 플래그 역추적
```bash
grep -rniE "flag" src | grep -v node_modules | head -50
```
- 플래그 위치: 파일, 환경 변수, DB, 관리자 쿠키, 관리자 전용 페이지
- 거기 닿으려면 무엇이 필요한가: 파일 읽기, 명령 실행, 관리자 권한, 관리자 브라우저에서의 스크립트 실행
- 관리자 봇(puppeteer, playwright, selenium)이 있으면 XSS·CSRF 계열을 먼저 본다.

## 3. 입력 지점 표
경로 × 입력 위치 × 처리 함수 표를 만든다. **쿼리, 본문(form·JSON), 쿠키, 헤더(Host, Referer, X-Forwarded-For 등), 업로드 파일 이름, WebSocket 메시지**를 모두 본다. 첫 화면의 로그인 폼만 파다가 다른 입력을 놓치는 일이 가장 흔하다.

## 4. 위험 함수 찾기
```bash
# PHP
grep -rnE "eval\(|system\(|exec\(|shell_exec|passthru|popen|include|require|unserialize|file_get_contents|extract\(|preg_replace|==\s*['\"]?0e|strcmp|md5\(" --include=*.php src
# Node.js
grep -rnE "eval\(|new Function|child_process|exec\(|spawn\(|vm\.|__proto__|constructor|merge\(|Object\.assign|res\.render\(|sendFile|path\.join|fetch\(|axios|request\(" --include=*.js --include=*.ts src | grep -v node_modules
# Python
grep -rnE "eval\(|exec\(|os\.system|subprocess|pickle\.loads|yaml\.load|render_template_string|open\(|requests\.(get|post)|urlopen|\.format\(|execute\(" --include=*.py src
# Java
grep -rnE "Runtime\.getRuntime|ProcessBuilder|ObjectInputStream|readObject|SpelExpression|lookup\(|createQuery\(" --include=*.java src
```
- 각 결과마다 입력이 실제로 닿는 호출 경로를 따라간다.

## 5. 인증·권한
- 로그인, 세션, JWT(서명 검증, 알고리즘, 키), 미들웨어가 붙는 경로와 빠진 경로, 관리자 판별 조건

## 6. 해석 차이
검사하는 쪽과 쓰는 쪽이 같은 값을 다르게 읽는지 본다.
- 미들웨어는 쿼리를 검사하는데 핸들러는 같은 이름을 JSON 본문에서 읽는다
- URL 파싱(`@`, `#`, `\`, 탭·개행, 인코딩 두 번), 경로 정규화(`../`, `..;/`, `%2e`)
- 배열·객체로 들어오는 값(`a[]=`, JSON 타입 바꾸기)
- 유니코드 정규화, 대소문자 비교, 프록시(nginx)와 앱의 라우팅 차이

## 7. 후보 순위
| 후보 | 근거 | 플래그까지 경로 | 확신 | 확인 비용 |
확신이 높고 확인이 싼 것부터.

## 8. 최소 PoC
- `solve.py`에 한 단계씩. 동작하면 바로 다음 단계로 간다. 다듬지 않는다.
- **능력을 얻은 즉시 2번에서 정한 플래그 위치로 간다.**

## 막혔을 때
- `notes.md` 시험 표에서 **미시험** 칸을 먼저 본다.
- 프레임워크·라이브러리 버전의 알려진 취약점, 문제 제목·설명의 힌트를 다시 본다.
- 일반 HTTP로 안 되는 통신(WebSocket 등)을 쓰는지 브라우저 네트워크 기록으로 확인한다.
- 정리하고 멈춘다: 확인된 사실 / 버린 가설과 이유 / 미시험 항목.
