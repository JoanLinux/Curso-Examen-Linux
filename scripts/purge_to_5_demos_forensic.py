import sqlite3

DB='/var/www/html/CursoLinux/instance/curso_linux.db'
KEEP_EMAILS={
 'demo.ia.alfa@uat.local',
 'demo.ia.beta@uat.local',
 'demo.ia.gamma@uat.local',
 'demo.ia.delta@uat.local',
 'demo.ia.epsilon@uat.local',
}

conn=sqlite3.connect(DB)
cur=conn.cursor()

# sesiones a conservar
tokens=[r[0] for r in cur.execute("SELECT session_token FROM exam_sessions WHERE student_email IN (?,?,?,?,?)", tuple(KEEP_EMAILS)).fetchall()]
marks=','.join(['?']*len(tokens)) if tokens else ''

# limpieza estricta por token
if tokens:
    cur.execute(f"DELETE FROM response_attempts WHERE session_token NOT IN ({marks})", tokens)
    cur.execute(f"DELETE FROM question_timing WHERE session_token NOT IN ({marks})", tokens)
    cur.execute(f"DELETE FROM responses WHERE session_token NOT IN ({marks})", tokens)
    cur.execute(f"DELETE FROM exam_archives WHERE session_token NOT IN ({marks})", tokens)
    cur.execute(f"DELETE FROM exam_sessions WHERE session_token NOT IN ({marks})", tokens)
else:
    cur.execute("DELETE FROM response_attempts")
    cur.execute("DELETE FROM question_timing")
    cur.execute("DELETE FROM responses")
    cur.execute("DELETE FROM exam_archives")
    cur.execute("DELETE FROM exam_sessions")

# limpia historial de reactivos para evitar restos de otros alumnos
cur.execute("DELETE FROM student_item_history WHERE student_key NOT LIKE 'email:demo.ia.%@uat.local'")

# normaliza secuencias
for t in ['responses','question_timing','response_attempts','exam_archives','student_item_history']:
    cur.execute("DELETE FROM sqlite_sequence WHERE name=?", (t,))

conn.commit()

# compactacion física para purgar páginas eliminadas
cur.execute("VACUUM")

# verificación
print('post_cleanup_counts')
for t in ['exam_sessions','responses','question_timing','response_attempts','exam_archives','student_item_history']:
    n=cur.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    print(t, n)

print('students')
for r in cur.execute("SELECT student_email, COUNT(*) FROM exam_sessions GROUP BY student_email ORDER BY student_email"):
    print(r[0], r[1])

conn.close()
