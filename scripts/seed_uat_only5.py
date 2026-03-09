import random
import sqlite3
import json
import uuid
from datetime import datetime, timedelta

DB = '/var/www/html/CursoLinux/instance/curso_linux.db'
random.seed(20260308)

ITEMS = [
    ("shell_grep_error_tail","shell","Ejercicio Shell: Filtrado de errores","grep -i error /var/log/syslog | tail -n 20"),
    ("cmd_net_ip_a","mcq","Comando red ip a","0"),
    ("cmd_last_recent_login","mcq","Ultimo login con last","0"),
    ("cmd_pkg_update_lists","mcq","Actualizar lista paquetes","0"),
    ("hist_kernel_author","mcq","Autor del kernel Linux","0"),
    ("cmd_whoami_user","mcq","Mostrar usuario actual","0"),
    ("shell_df_human","shell","Ejercicio Shell: Espacio en disco","df -h"),
    ("shell_find_logs_recent","shell","Ejercicio Shell: Buscar logs recientes","find /var/log -type f -name '*.log' -mtime -2"),
    ("cmd_proc_kill","mcq","Terminar proceso por PID","0"),
    ("cmd_net_ping","mcq","Ping host interno","0"),
]

PROFILES = [
    {"name":"Demo IA Alfa","email":"demo.ia.alfa@uat.local","base_acc":0.85,"base_time":70,"resets":1,"tier":1},
    {"name":"Demo IA Beta","email":"demo.ia.beta@uat.local","base_acc":0.74,"base_time":95,"resets":2,"tier":2},
    {"name":"Demo IA Gamma","email":"demo.ia.gamma@uat.local","base_acc":0.63,"base_time":120,"resets":2,"tier":2},
    {"name":"Demo IA Delta","email":"demo.ia.delta@uat.local","base_acc":0.52,"base_time":155,"resets":3,"tier":3},
    {"name":"Demo IA Epsilon","email":"demo.ia.epsilon@uat.local","base_acc":0.41,"base_time":210,"resets":4,"tier":4},
]

ATTEMPTS_PER_STUDENT = 10


def iso(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def delete_sessions(cur, tokens):
    if not tokens:
        return
    marks = ','.join(['?'] * len(tokens))
    cur.execute(f"DELETE FROM response_attempts WHERE session_token IN ({marks})", tokens)
    cur.execute(f"DELETE FROM question_timing WHERE session_token IN ({marks})", tokens)
    cur.execute(f"DELETE FROM responses WHERE session_token IN ({marks})", tokens)
    cur.execute(f"DELETE FROM exam_archives WHERE session_token IN ({marks})", tokens)
    cur.execute(f"DELETE FROM exam_sessions WHERE session_token IN ({marks})", tokens)


def main():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    now = datetime.utcnow()

    # 1) Remove all previous fictitious/example users
    tokens = [r[0] for r in cur.execute(
        """
        SELECT session_token
        FROM exam_sessions
        WHERE student_email LIKE 'demo.%@uat.local'
           OR student_email LIKE '%qa_ml_student_%@example.com'
           OR student_name LIKE 'Demo ML %'
           OR student_name LIKE 'QA ML %'
        """
    ).fetchall()]
    delete_sessions(cur, tokens)

    # 2) Seed only 5 demo students with 10 random solved exams each
    sessions_inserted = 0
    for sidx, p in enumerate(PROFILES):
        for aidx in range(ATTEMPTS_PER_STUDENT):
            token = f"ml5-{sidx+1:02d}-{aidx+1:02d}-{uuid.uuid4().hex[:8]}"
            started = now - timedelta(days=(25 - aidx), hours=(sidx * 2), minutes=(aidx * 4 + sidx))
            total = len(ITEMS)

            acc = min(0.97, p['base_acc'] + aidx * 0.012)
            correct_target = max(0, min(total, int(round(total * acc))))
            correctness = [1]*correct_target + [0]*(total-correct_target)
            random.shuffle(correctness)

            payload = [{"id":x[0], "type":x[1], "prompt":x[2]} for x in ITEMS]
            elapsed = 0
            score = 0
            responses = []
            timings = []
            attempts = []

            for i, (iid, itype, prompt, expected) in enumerate(ITEMS):
                ok = int(correctness[i])
                if ok:
                    score += 1
                sec = max(15, int(random.gauss(p['base_time'], p['base_time']*0.22)))
                elapsed += sec
                submitted = started + timedelta(seconds=elapsed)

                if itype == 'shell':
                    if ok:
                        ua = expected
                        trace = [expected]
                    else:
                        ua = 'echo intento'
                        trace = [ua]
                else:
                    ua = '0' if ok else random.choice(['1','2','3'])
                    trace = []

                responses.append((token, i, iid, itype, prompt, ua, ok, expected, iso(submitted), '', json.dumps(trace), ''))
                timings.append((token, i, float(sec), None))
                attempts.append((token, i, iid, 1, ua, ok, iso(submitted - timedelta(seconds=2))))
                if ok == 0 and random.random() < 0.55:
                    second_ok = 1 if random.random() < (0.70 - p['tier']*0.08) else 0
                    second_ans = expected if second_ok else ua + ' --retry'
                    attempts.append((token, i, iid, 2, second_ans, second_ok, iso(submitted - timedelta(seconds=1))))

            finished = started + timedelta(seconds=elapsed + random.randint(30, 180))

            cur.execute(
                """
                INSERT INTO exam_sessions
                (session_token, student_name, student_email, started_at, finished_at, current_index, total_items, completed, score, exam_payload, resets_count, max_reached_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (token, p['name'], p['email'], iso(started), iso(finished), total, total, 1, score, json.dumps(payload), p['resets'], total-1)
            )
            cur.executemany(
                """
                INSERT INTO responses
                (session_token,item_index,item_id,item_type,prompt,user_answer,is_correct,expected,submitted_at,distro_guess,command_trace,extra_text)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                responses
            )
            cur.executemany(
                "INSERT INTO question_timing (session_token,item_index,seconds_spent,last_entered_at) VALUES (?,?,?,?)",
                timings
            )
            cur.executemany(
                "INSERT INTO response_attempts (session_token,item_index,item_id,attempt_no,user_answer,is_correct,submitted_at) VALUES (?,?,?,?,?,?,?)",
                attempts
            )
            sessions_inserted += 1

    conn.commit()

    print('seed_done')
    print('sessions_inserted', sessions_inserted)
    for p in PROFILES:
        c = cur.execute("SELECT COUNT(*) FROM exam_sessions WHERE student_email=?", (p['email'],)).fetchone()[0]
        print(p['email'], c)

    conn.close()


if __name__ == '__main__':
    main()
