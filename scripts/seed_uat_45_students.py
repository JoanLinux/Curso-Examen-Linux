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

N_STUDENTS = 45
ATTEMPTS_PER_STUDENT = 10

TIER_PARAMS = [
    # (base_acc, base_time_sec, resets)
    (0.92, 55, 0),
    (0.82, 75, 1),
    (0.70, 105, 2),
    (0.56, 145, 3),
    (0.42, 210, 5),
]

FIRST_NAMES = [
    "Alan","Brenda","Carlos","Diana","Edgar","Fernanda","Gustavo","Hilda","Ivan","Jimena",
    "Kevin","Laura","Marco","Nadia","Oscar","Paola","Ramon","Sofia","Tomas","Uriel",
    "Valeria","Wendy","Ximena","Yahir","Zulema","Andres","Beatriz","Cesar","Denisse","Esteban",
    "Fatima","Gerardo","Helena","Irving","Julieta","Karla","Leonardo","Monica","Nestor","Olga",
    "Pablo","Quetzal","Rocio","Salvador","Teresa"
]
LAST_NAMES = ["Demo","Practica","UAT","Linux"]


def iso(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def build_profiles():
    out = []
    for i in range(1, N_STUDENTS + 1):
        tier = (i - 1) // 9  # 5 tiers x 9 = 45
        base_acc, base_time, resets = TIER_PARAMS[tier]
        name = f"{FIRST_NAMES[i-1]} {random.choice(LAST_NAMES)} {i:02d}"
        email = f"demo.ia.{i:02d}@uat.local"
        out.append({
            "name": name,
            "email": email,
            "base_acc": base_acc,
            "base_time": base_time,
            "resets": resets,
            "tier": tier,
        })
    return out


def main():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    now = datetime.utcnow()

    profiles = build_profiles()
    emails = [p["email"] for p in profiles]

    # Cleanup previous demo seeds only
    qmarks = ",".join(["?"] * len(emails))
    old_tokens = [r[0] for r in cur.execute(
        f"SELECT session_token FROM exam_sessions WHERE student_email IN ({qmarks})",
        emails,
    ).fetchall()]

    if old_tokens:
        tmarks = ",".join(["?"] * len(old_tokens))
        cur.execute(f"DELETE FROM response_attempts WHERE session_token IN ({tmarks})", old_tokens)
        cur.execute(f"DELETE FROM question_timing WHERE session_token IN ({tmarks})", old_tokens)
        cur.execute(f"DELETE FROM responses WHERE session_token IN ({tmarks})", old_tokens)
        cur.execute(f"DELETE FROM exam_archives WHERE session_token IN ({tmarks})", old_tokens)
        cur.execute(f"DELETE FROM exam_sessions WHERE session_token IN ({tmarks})", old_tokens)

    sessions_inserted = 0
    responses_inserted = 0

    for sidx, p in enumerate(profiles):
        for aidx in range(ATTEMPTS_PER_STUDENT):
            token = f"ml45-{sidx+1:02d}-{aidx+1:02d}-{uuid.uuid4().hex[:8]}"
            started = now - timedelta(days=(50 - aidx), hours=(sidx % 12), minutes=(aidx * 5 + sidx % 7))
            total = len(ITEMS)

            # slight progress on each attempt
            acc = min(0.98, p["base_acc"] + aidx * 0.012)
            correct_target = int(round(total * acc))
            correct_target = max(0, min(total, correct_target))

            correctness = [1] * correct_target + [0] * (total - correct_target)
            random.shuffle(correctness)

            # Payload summary for session
            payload = [{"id": x[0], "type": x[1], "prompt": x[2]} for x in ITEMS]

            resp_rows = []
            t_rows = []
            att_rows = []

            elapsed = 0
            score = 0
            syntax_bias = 0.20 + p["tier"] * 0.12

            for i, (iid, itype, prompt, expected) in enumerate(ITEMS):
                is_ok = int(correctness[i])
                if is_ok:
                    score += 1

                sec = max(14, int(random.gauss(p["base_time"], p["base_time"] * 0.25)))
                elapsed += sec
                submitted = started + timedelta(seconds=elapsed)

                if itype == "shell":
                    if is_ok:
                        ua = expected
                        trace = [expected]
                    else:
                        if random.random() < syntax_bias:
                            ua = expected + " --bad"
                        else:
                            ua = "echo prueba"
                        trace = [ua]
                else:
                    ua = "0" if is_ok else random.choice(["1", "2", "3"])
                    trace = []

                resp_rows.append((
                    token, i, iid, itype, prompt, ua, is_ok, expected, iso(submitted), "", json.dumps(trace), ""
                ))
                t_rows.append((token, i, float(sec), None))
                att_rows.append((token, i, iid, 1, ua, is_ok, iso(submitted - timedelta(seconds=2))))

                # Generate some second attempts on wrong answers
                if is_ok == 0 and random.random() < 0.60:
                    second_ok = 1 if random.random() < (0.72 - p["tier"] * 0.10) else 0
                    second_ans = expected if second_ok else ua + " #retry"
                    att_rows.append((token, i, iid, 2, second_ans, second_ok, iso(submitted - timedelta(seconds=1))))

            finished = started + timedelta(seconds=elapsed + random.randint(30, 180))

            cur.execute(
                """
                INSERT INTO exam_sessions
                (session_token, student_name, student_email, started_at, finished_at, current_index, total_items, completed, score, exam_payload, resets_count, max_reached_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (token, p["name"], p["email"], iso(started), iso(finished), total, total, 1, score, json.dumps(payload), p["resets"], total - 1),
            )
            cur.executemany(
                """
                INSERT INTO responses
                (session_token, item_index, item_id, item_type, prompt, user_answer, is_correct, expected, submitted_at, distro_guess, command_trace, extra_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                resp_rows,
            )
            cur.executemany(
                """
                INSERT INTO question_timing
                (session_token, item_index, seconds_spent, last_entered_at)
                VALUES (?, ?, ?, ?)
                """,
                t_rows,
            )
            cur.executemany(
                """
                INSERT INTO response_attempts
                (session_token, item_index, item_id, attempt_no, user_answer, is_correct, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                att_rows,
            )

            sessions_inserted += 1
            responses_inserted += len(resp_rows)

    conn.commit()

    print(f"seed_ok students={N_STUDENTS} attempts_each={ATTEMPTS_PER_STUDENT} sessions={sessions_inserted} responses={responses_inserted}")
    for p in profiles[:5]:
        c = cur.execute("SELECT COUNT(*) FROM exam_sessions WHERE student_email=?", (p["email"],)).fetchone()[0]
        print(p["email"], c)

    conn.close()


if __name__ == '__main__':
    main()
