import sqlite3
import json
import uuid
import random
from datetime import datetime, timedelta

random.seed(42)
DB='/var/www/html/CursoLinux/instance/curso_linux.db'

conn=sqlite3.connect(DB)
cur=conn.cursor()
now=datetime.utcnow()

def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

items=[
    ("shell_grep_error_tail","shell","Ejercicio Shell: Filtrado de errores","grep -i error /var/log/syslog | tail -n 20"),
    ("cmd_net_ip_a","mcq","Comando red ip a","0"),
    ("cmd_last_recent_login","mcq","Ultimo login con last","0"),
    ("cmd_pkg_update_lists","mcq","Actualizar lista paquetes","0"),
    ("hist_kernel_author","mcq","Autor del kernel Linux","0"),
    ("cmd_whoami_user","mcq","Mostrar usuario actual","0"),
    ("shell_df_human","shell","Ejercicio Shell: Espacio en disco","df -h"),
    ("shell_find_logs_recent","shell","Ejercicio Shell: Buscar logs recientes","find /var/log -type f -name '*.log' -mtime -2"),
]

profiles=[
    {"name":"Demo ML Excelente","email":"demo.ml.excelente@uat.local","base_acc":0.90,"time":55,"resets":0,"dropouts":0,"syntax":0.25},
    {"name":"Demo ML Bueno","email":"demo.ml.bueno@uat.local","base_acc":0.78,"time":85,"resets":1,"dropouts":0,"syntax":0.35},
    {"name":"Demo ML Intermedio","email":"demo.ml.intermedio@uat.local","base_acc":0.62,"time":120,"resets":2,"dropouts":1,"syntax":0.45},
    {"name":"Demo ML Riesgo Medio","email":"demo.ml.riesgo.medio@uat.local","base_acc":0.48,"time":165,"resets":3,"dropouts":2,"syntax":0.55},
    {"name":"Demo ML Riesgo Alto","email":"demo.ml.riesgo.alto@uat.local","base_acc":0.34,"time":230,"resets":5,"dropouts":3,"syntax":0.65},
]

# cleanup old demo rows
emails=[p['email'] for p in profiles]
qmarks=','.join('?' for _ in emails)
old_tokens=[r[0] for r in cur.execute(f"SELECT session_token FROM exam_sessions WHERE student_email IN ({qmarks})", emails).fetchall()]
if old_tokens:
    tmarks=','.join('?' for _ in old_tokens)
    cur.execute(f"DELETE FROM response_attempts WHERE session_token IN ({tmarks})", old_tokens)
    cur.execute(f"DELETE FROM question_timing WHERE session_token IN ({tmarks})", old_tokens)
    cur.execute(f"DELETE FROM responses WHERE session_token IN ({tmarks})", old_tokens)
    cur.execute(f"DELETE FROM exam_archives WHERE session_token IN ({tmarks})", old_tokens)
    cur.execute(f"DELETE FROM exam_sessions WHERE session_token IN ({tmarks})", old_tokens)

created=[]

for sidx,p in enumerate(profiles):
    for attempt in range(10):
        token=f"mlseed-{sidx+1}-{attempt+1}-{uuid.uuid4().hex[:8]}"
        started=now - timedelta(days=(12-attempt), hours=sidx, minutes=attempt*7)
        completed=True
        if attempt < p['dropouts']:
            completed=False
        total=len(items)
        answered=total if completed else random.randint(3,6)

        acc=min(0.98, p['base_acc'] + (attempt*0.015))
        correct_target=max(0,min(answered, int(round(answered*acc))))

        responses=[]
        correctness=[1]*correct_target + [0]*(answered-correct_target)
        random.shuffle(correctness)

        total_seconds=0
        for i in range(answered):
            iid,itype,prompt,expected=items[i]
            is_ok=correctness[i]
            sec=max(18, int(random.gauss(p['time'], p['time']*0.25)))
            total_seconds += sec
            submitted=started + timedelta(seconds=total_seconds)

            if itype=='shell':
                if is_ok:
                    ua=expected
                    trace=[expected]
                else:
                    wrong='grep error /var/log/syslog' if 'grep' in expected else 'df'
                    ua=wrong
                    trace=[wrong]
            else:
                ua='0' if is_ok else '2'
                trace=[]

            responses.append((token,i,iid,itype,prompt,ua,is_ok,expected,iso(submitted),'',json.dumps(trace),''))

            cur.execute("INSERT INTO question_timing (session_token,item_index,seconds_spent,last_entered_at) VALUES (?,?,?,NULL)", (token,i,sec))
            cur.execute(
                "INSERT INTO response_attempts (session_token,item_index,item_id,attempt_no,user_answer,is_correct,submitted_at) VALUES (?,?,?,?,?,?,?)",
                (token,i,iid,1,ua,is_ok,iso(submitted - timedelta(seconds=3)))
            )
            if is_ok==0 and random.random()<0.55:
                second_ok = 1 if random.random() < (0.75 - p['syntax']*0.2) else 0
                second_ans = expected if second_ok else ua + ' -bad'
                cur.execute(
                    "INSERT INTO response_attempts (session_token,item_index,item_id,attempt_no,user_answer,is_correct,submitted_at) VALUES (?,?,?,?,?,?,?)",
                    (token,i,iid,2,second_ans,second_ok,iso(submitted - timedelta(seconds=1)))
                )

        score=sum(1 for r in responses if r[6]==1)
        current_index=answered if not completed else total
        max_reached=max(0, answered-1)
        finished = (started + timedelta(seconds=total_seconds + random.randint(45,240))) if completed else None

        payload=[{"id":x[0],"type":x[1],"prompt":x[2]} for x in items]
        cur.execute(
            """
            INSERT INTO exam_sessions
            (session_token, student_name, student_email, started_at, finished_at, current_index, total_items, completed, score, exam_payload, resets_count, max_reached_index)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (token,p['name'],p['email'],iso(started), iso(finished) if finished else None, current_index,total,1 if completed else 0,score,json.dumps(payload), p['resets'] if attempt%3==0 else max(0,p['resets']-1), max_reached)
        )

        cur.executemany(
            """
            INSERT INTO responses
            (session_token,item_index,item_id,item_type,prompt,user_answer,is_correct,expected,submitted_at,distro_guess,command_trace,extra_text)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            responses
        )

    created.append((p['name'],p['email']))

conn.commit()
print('seed_done')
for name,email in created:
    n=cur.execute("SELECT COUNT(*) FROM exam_sessions WHERE student_email=?", (email,)).fetchone()[0]
    print(name,email,'sessions',n)

conn.close()
