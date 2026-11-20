# panda — Write-Up

- 분야: 웹 (블랙박스, 소스 없음)
- 플래그: `PD{mv1G2IJYVD9LhBzx07vgRvk7EUSVC3VH2Pu2y5}`
- 푼 시각: 2026-11-20

## 요약
모든 기능이 받는 "식(formula)"이 PostgreSQL 쿼리에 그대로 들어가는 SQL 인젝션입니다.
기능마다 DB 계정이 다르고, 계정마다 8바이트 열쇠 조각(capsule)을 하나씩 읽을 수 있습니다.
기능마다 다른 통로로 조각 5개를 모아 unlock_key를 만들었습니다.
그 키로 report worker 안에서 `worker_shadow.unseal_index`를 불러 암호문을 받았고, 로컬에서 복호화했습니다.

## 분석
1. **처음 본 것**: Burp 기록(`out/burp_dump.txt`)을 보면 search, check, charts, audit, export, report 모두 같은 형식 `{"index":{"kind":"formula","expr":...}}`을 받습니다. `quality_score::text` 같은 기본값과 `invalid input syntax for type numeric` 오류로 보아 DB는 PostgreSQL입니다.
2. **오류 노출**: audit에 `('x'||(SELECT ...))`를 넣으면 숫자 변환이 실패하고, `engine_error`에 값이 그대로 찍힙니다. 이걸로 스키마, 권한, 함수 정의를 덤프했습니다(`out/funcs.txt`, `out/enum4.txt`).
3. **플래그 위치와 조건**: 플래그는 `vault.secret_chunks`에 있고 `worker_shadow.unseal_index(i, proof)`로만 꺼낼 수 있습니다. 조건은 다음과 같습니다.
   - report worker 계정이어야 합니다.
   - run이 실행 중이어야 합니다.
   - proof는 `HMAC-SHA256(unlock_key, "report-proof\0" ‖ 계정 이름들 ‖ report_id ‖ run_id ‖ i)`여야 합니다.
4. **unlock_key 규칙**: `archive_stage.worker_manifest` 표에 있습니다(`out/manifest.txt`).
   - `sha256("Indexed Hollow seal v3\0" ‖ R‖T‖C‖A‖E)`
   - 암호문 조각 n은 `HMAC(key, "flag-stream\0" ‖ int4(n))`와 XOR하면 풀립니다.

## 풀이
조각 5개를 각 기능의 통로로 읽었습니다(`out/capsules.txt`).

| 조각 | 기능(DB 계정) | 통로 | 값 |
|---|---|---|---|
| R route | search | 정렬 순서 (참이면 역순) | `50deff7918bca4b0` |
| T clock | check | 응답 시간 (`pg_sleep`) | `66d4c1a740467822` |
| C chart | charts | `fold_chart` 집계 결과가 숫자로 그대로 나옴 | `3ff36382c845952e` |
| A audit | audit | 오류 메시지 | `d7b8686a714cd93a` |
| E export | export | 응답이 고정이라, 표를 읽은 횟수(`pg_stat_all_tables.seq_scan`)를 audit에서 읽음 | `0f66ebdf74e2fc0d` |

1. 조각으로 `unlock_key = 55d9d088…a939a`를 만들었습니다. worker에서 `unseal_index`가 NULL이 아닌 값을 돌려줘서 맞는 키임을 확인했습니다(`out/worker3.txt`).
2. report 식 안에서 `crypto.hmac`로 proof를 계산했습니다. report_id와 run_id는 worker 안에서만 `current_setting`으로 알 수 있기 때문입니다.
3. `worker_shadow.unseal_index`를 불렀습니다. 행마다 조각 번호를 다르게 넣어 run 2번으로 암호문 6조각을 받았습니다.
4. 함수 이름에는 스키마를 꼭 붙여야 합니다. worker의 search_path가 `app, worker_shadow` 순서라서, 그냥 `unseal_index`라고 쓰면 미끼 함수 `app.unseal_index`가 불립니다.

전체 코드는 `exploit.py`에 있습니다. 핵심은 이 부분입니다.

```python
key = hashlib.sha256(b"Indexed Hollow seal v3\0" + R + T + C + A + E).digest()
proof = f"encode(crypto.hmac({msg},'\\x{key.hex()}'::bytea,'sha256'),'hex')"
report(f"{i}::text||'='||coalesce(worker_shadow.unseal_index({i},{proof}),'')")
pt = ct[n] XOR hmac(key, b"flag-stream\0" + int4(n))
```

## 플래그가 나온 응답
```
GET /api/reports/27fe46e8-…/runs/5ac0b86c-…   (out/worker4.txt)
{"artifact":{"rows":[{"grove_code":"IH-001",…,"sealed_index":"0=6a5c2d7c1cbc06c0"},
                     {"grove_code":"IH-002",…,"sealed_index":"1=d53202a6ac059b71"}, …]},"state":"complete"}
GET /api/reports/01146cd9-…/runs/3e3c5846-…
… "4=56aa1f21f9d833b7" … "5=ea66" …
```
- 서버가 준 암호문(원래 문자열): `6a5c2d7c1cbc06c0:d53202a6ac059b71:d5c070c6c060ba65:948764eedefc8d02:56aa1f21f9d833b7:ea66`
- 로컬에서 복호화한 결과: `PD{mv1G2IJYVD9LhBzx07vgRvk7EUSVC3VH2Pu2y5}`

## 도구·도움
- 사용 도구: Burp(기능 기록, 사람이 수집), python requests, 직접 짠 스크립트(`probe.py`, `exploit.py`)
- AI 사용 여부와 범위: Claude Code(claude-opus-5-5)가 Burp 기록 분석, 요청 전송, 추출, 복호화를 했습니다. 사람은 Burp 수집과 진행 지시를 했습니다.
