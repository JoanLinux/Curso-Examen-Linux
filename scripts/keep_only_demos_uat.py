import sqlite3

DB='/var/www/html/CursoLinux/instance/curso_linux.db'
conn=sqlite3.connect(DB)
cur=conn.cursor()

# Tokens a conservar (solo demos actuales)
keep_tokens=[r[0] for r in cur.execute(
    "SELECT session_token FROM exam_sessions WHERE student_email LIKE 'demo.ia.%@uat.local'"
).fetchall()]

if keep_tokens:
    marks=','.join(['?']*len(keep_tokens))
    # borrar todo lo que NO sea demo
    cur.execute(f"DELETE FROM response_attempts WHERE session_token NOT IN ({marks})", keep_tokens)
    cur.execute(f"DELETE FROM question_timing WHERE session_token NOT IN ({marks})", keep_tokens)
    cur.execute(f"DELETE FROM responses WHERE session_token NOT IN ({marks})", keep_tokens)
    cur.execute(f"DELETE FROM exam_archives WHERE session_token NOT IN ({marks})", keep_tokens)
    cur.execute(f"DELETE FROM exam_sessions WHERE session_token NOT IN ({marks})", keep_tokens)
else:
    # no hay demos, borra todo
    cur.execute("DELETE FROM response_attempts")
    cur.execute("DELETE FROM question_timing")
    cur.execute("DELETE FROM responses")
    cur.execute("DELETE FROM exam_archives")
    cur.execute("DELETE FROM exam_sessions")

conn.commit()

# reporte
cnt_sessions=cur.execute("SELECT COUNT(*) FROM exam_sessions").fetchone()[0]
cnt_resp=cur.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
cnt_tim=cur.execute("SELECT COUNT(*) FROM question_timing").fetchone()[0]
cnt_att=cur.execute("SELECT COUNT(*) FROM response_attempts").fetchone()[0]
demo_students=cur.execute("SELECT COUNT(DISTINCT student_email) FROM exam_sessions WHERE student_email LIKE 'demo.ia.%@uat.local'").fetchone()[0]
print('sessions', cnt_sessions)
print('responses', cnt_resp)
print('timings', cnt_tim)
print('attempts', cnt_att)
print('demo_students', demo_students)
for r in cur.execute("SELECT student_email, COUNT(*) FROM exam_sessions GROUP BY student_email ORDER BY student_email"):
    print(r[0], r[1])

conn.close()
