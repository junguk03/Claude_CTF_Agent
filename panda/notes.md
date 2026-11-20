# panda

대상: http://host3.dreamhack.games:16325
플래그 형식: PD{...}
소스: 없음 (블랙박스). Burp 기록 src/burp.xml (157건) → 정리본 out/burp_dump.txt
문제 설명: "Indexed Hollow" — 기록 장치가 대나무 길을 정렬. 봉인된 숲(sealed grove)은 직접 안 보임.
  힌트: 길의 순서(ORDER BY), 오류(error), 남겨진 보고서(report worker 결과).

## 현재 상태
- 계정·세션: 쿠키 `ih_guest` (`/`에서 발급, base64 JSON `{"tenant":"<uuid>","v":1}` + 서명 32바이트 추정). HttpOnly.
- 확보한 능력 (probe.py에 함수로 있음):
  - audit(`audit_reader`): 오류 기반 SQLi `('x'||(SELECT ...))` → engine_error에 문자열 노출(~200자 잘림, substr로 나눠 읽음). statement_timeout 220ms. pg_catalog·pg_stat_*·pg_locks 조회 가능.
  - search(`search_reader`): 정렬 오라클 `s_or(cond)` (참→역순)
  - check(`probe_reader`): pg_sleep 시간 오라클 `t_or(cond)`
  - charts(`chart_reader`): 숫자 직접 반사 (avg_index)
  - export(`analytics_reader`): 응답 고정. **seq_scan 카운터 부채널** `x_send(valexpr)` — export 식에서 표를 N+1번 rescan → audit에서 pg_stat_all_tables.seq_scan 증가량으로 N 읽음 (1요청=1바이트, ~2.3초)
- capsule (각 8바이트):
  - route  (search)  = 50deff7918bca4b0
  - clock  (check)   = 66d4c1a740467822
  - chart  (charts, fold_chart 집계→chart_fold_final) = 3ff36382c845952e (=4608136257087051054)
  - audit  (audit)   = d7b8686a714cd93a
  - export (export)  = 0f66ebdf74e2fc0d
- 플래그 위치: `vault.secret_chunks(chunk_index 0..15, ciphertext)` — `worker_shadow.unseal_index(i, proof)`만 꺼냄.
  조건: session_user=report_worker, report_runs.state='running', app.context_is_valid('worker','sealed',...), proof = HMAC-SHA256(unlock_key, 'report-proof\0'||len(session_user)||session_user||len(current_user)||current_user||uuid(report)||uuid(run)||int4(i)).
  unlock_key는 vault.seal_control (직접 못 읽음) → capsule 5개+worker_manifest로 유도된다고 추정.

## 결과 — 플래그 후보
**PD{mv1G2IJYVD9LhBzx07vgRvk7EUSVC3VH2Pu2y5}**
- manifest (export 카운터 부채널, out/manifest.txt): share_order=R,T,C,A,E, share_sizes=8×5, unlock_hash=sha256,
  unlock_domain_hex=496e6465...00 ("Indexed Hollow seal v3\0"), stream_domain_hex=666c61672d73747265616d00 ("flag-stream\0"),
  chunk_count=6, chunk_size=8, ciphertext_join=colon,index-ascending
- unlock_key = sha256(unlock_domain ‖ route‖clock‖chart‖audit‖export 원시 바이트)
  = 55d9d088d01da797b665993a481e07c28c58758446f4c7abdd77b023ca6a939a (worker에서 unseal_index가 NULL 아님으로 검증, out/worker3.txt)
- 서버 응답 암호문 (report run artifact, out/worker4.txt, run 5ac0b86c…, 3e3c5846…):
  6a5c2d7c1cbc06c0:d53202a6ac059b71:d5c070c6c060ba65:948764eedefc8d02:56aa1f21f9d833b7:ea66
- 복호화(로컬): chunk i 평문 = ct_i XOR HMAC-SHA256(unlock_key, stream_domain ‖ int4_be(i))[:len]
- report 식 (행마다 chunk 번호 = grove_code 숫자-1+off): `worker_shadow.unseal_index(i, encode(crypto.hmac('report-proof\0'‖int2(30)‖session_user‖int2(26)‖'app_owner_7bad043ad9287146'‖uuid(report_id)‖uuid(run_id)‖int4(i), unlock_key,'sha256'),'hex'))` — probe.py proof_sql()
- 주의: search_path가 `app, worker_shadow`라 그냥 unseal_index는 미끼 app.unseal_index로 감.

## 엔드포인트 (burp.xml 기준)
| 경로 | 본문 | 응답 |
|---|---|---|
| GET / | - | HTML, Set-Cookie ih_guest |
| POST /api/search | `{"index":{kind,...}}` | rows 4개 (grove 목록), 정렬만 바뀜 |
| POST /api/formulas/check | 동일 | `{"state":"checked"}` 만 (실행 시간만 보인다고 설명 → 시간 기반) |
| POST /api/charts | 동일 | region별 avg_index |
| POST /api/audit | `{"index":..., "query":"harvest"}` | rows 5개 + 실패 시 `engine_error` (DB 오류 일부) |
| POST /api/export | 동일 | CSV, index_band (prime/select/standard) |
| POST /api/reports/save | `{"name","definition":{"version":1,"index":{kind:"formula",expr}},"report_id"?}` | report_id, revision_id, sha256 |
| POST /api/reports/run | `{"report_id"}` | run_id, pending |
| GET /api/reports/<rid>/runs/<run> | - | complete 시 artifact.rows[].sealed_index = 식 결과 그대로 |

index 형태: `{"kind":"field","name":X}` / `{"kind":"literal","value":X}` / `{"kind":"formula","expr":X}`

## 시험 표
| 경로 | 입력 위치 | 유형 | 결과 | 근거 |
|---|---|---|---|---|
| /api/search | index.formula.expr | ORDER BY 식 주입(정렬 오라클) | 미시험 (정상식 `quality_score\n` 200) | burp #7 |
| /api/search | index.field.name / literal | 동일 | 응답 없음(burp 기록 status None) | burp #1,2,6 |
| /api/formulas/check | expr | 시간 기반 | 미시험 | burp #3-5 |
| /api/charts | expr | 정렬/집계 변화 | 미시험 (formula 시 정렬 바뀜) | burp #9,10 |
| /api/audit | literal.value | 오류 기반(engine_error) | **오류 노출 확인** — PostgreSQL 메시지 `invalid input syntax for type numeric` | burp #12 |
| /api/audit | formula.expr | 오류 기반 | 미시험 | |
| /api/audit | query | SQLi | 미시험 | |
| /api/export | expr | index_band 변화 | 미시험 | |
| /api/reports/save+run | definition.index.expr | 결과 직접 반사(sealed_index) | **식 결과가 그대로 나옴** (`quality_score::text`) | burp run 5fecdf16 |
| /api/reports/save | name, version, report_id | 기타 | 미시험 | |
| 쿠키 ih_guest | tenant | 위조/타 tenant | 미시험 | |

## 확인된 사실
- 서버 gunicorn(파이썬), DB는 PostgreSQL (`::text` 캐스트, numeric 오류 문구).
- report run 결과 `sealed_index`에 식 결과 문자열이 그대로 나옴 → 직접 반사 채널 후보.
- 많은 run이 pending에서 멈춤 (93번 폴링도 pending) → 워커가 늦거나 조건 있음.

- DB 역할: app_owner_7bad..., data_owner_1910..., search_reader, probe_reader, chart_reader, audit_reader, analytics_reader, report_store, report_dispatcher, report_worker_4d6cb67b49082ac6, ih_pg. 함수·뷰 정의 out/funcs.txt, ACL out/enum4.txt.
- worker는 archive_stage 스키마 USAGE 없음, crypto.hmac/digest(bytea) 실행 가능.

## 버린 가설과 이유
- export 응답으로 직접 유출: 어떤 식/형식도 응답·시간 고정(~1.55초) → 카운터 부채널로 대체

## 미시험
- /static/app.js 내용
- formula 식에서 서브쿼리 `(SELECT ...)` 허용 여부

## 진행 기록 (블로그용)
| 시각 | 한 일 | 결과 | 사람 개입 |
|---|---|---|---|
| 11-20 | manifest 추출 → unlock_key 검증 → worker로 암호문 6조각 → 로컬 복호화 | 플래그 후보 PD{mv1G…y5} | 없음 |
| 11-20 | audit 오류 SQLi → 스키마/함수 덤프, 각 역할별 capsule 유출 | capsule 5개 확보 | 없음 |
| 11-20 | burp.xml 파싱, 시험 표 작성 | 엔드포인트 9개, 오류 노출/반사 채널 확인 | burp 수집은 사람 |
