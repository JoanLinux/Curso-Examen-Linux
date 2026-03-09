import json
import random
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import DISTRO_ROTATION, build_exam, student_key_for_cycle


PROFILES = [
    {"name": "Demo Uno", "email": "demo.uno@ficticio.local", "acc": 0.58, "base_sec": 95, "resets": 1},
    {"name": "Demo Dos", "email": "demo.dos@ficticio.local", "acc": 0.64, "base_sec": 88, "resets": 1},
    {"name": "Demo Tres", "email": "demo.tres@ficticio.local", "acc": 0.71, "base_sec": 82, "resets": 0},
    {"name": "Demo Cuatro", "email": "demo.cuatro@ficticio.local", "acc": 0.77, "base_sec": 76, "resets": 0},
    {"name": "Demo Cinco", "email": "demo.cinco@ficticio.local", "acc": 0.84, "base_sec": 70, "resets": 0},
]

ATTEMPTS_PER_STUDENT = 3
RANDOM_SEED = 20260309


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clear_all_data(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    for table in [
        "response_attempts",
        "question_timing",
        "responses",
        "exam_archives",
        "exam_sessions",
        "student_item_history",
    ]:
        cur.execute(f"DELETE FROM {table}")
    cur.execute("DELETE FROM sqlite_sequence")
    conn.commit()


def make_wrong_mcq(correct: int, choices: int) -> str:
    pool = [i for i in range(choices) if i != correct]
    return str(random.choice(pool)) if pool else str(correct)


def seed(conn: sqlite3.Connection) -> None:
    random.seed(RANDOM_SEED)
    now = datetime.utcnow()
    cur = conn.cursor()

    inserted_sessions = 0
    for pidx, p in enumerate(PROFILES):
        for attempt in range(ATTEMPTS_PER_STUDENT):
            token = f"demo53-{pidx+1:02d}-{attempt+1:02d}-{uuid.uuid4().hex[:8]}"
            started = now - timedelta(days=(12 - attempt), minutes=(pidx * 9 + attempt * 4))
            student_key = student_key_for_cycle(p["name"], p["email"])
            items = build_exam(student_key=student_key, conn=conn)
            total = len(items)
            score = 0
            elapsed = 0
            payload = []
            responses = []
            timings = []
            attempts_rows = []

            acc_target = min(0.95, p["acc"] + attempt * 0.06)

            for idx, item in enumerate(items):
                payload.append(item)
                is_correct = random.random() < acc_target
                seconds = max(15, int(random.gauss(p["base_sec"], p["base_sec"] * 0.25)))
                elapsed += seconds
                submitted_at = started + timedelta(seconds=elapsed)

                answer = ""
                command_trace = []
                distro_guess = ""
                extra_text = ""
                expected = str(item.get("expected", item.get("correct", "")))

                if item["type"] == "mcq":
                    correct_idx = int(item["correct"])
                    answer = str(correct_idx) if is_correct else make_wrong_mcq(correct_idx, len(item.get("choices", [])))
                elif item["type"] == "image_click":
                    answer = str(item["correct"]) if is_correct else "cpu"
                else:
                    expected = str(item.get("expected", ""))
                    answer = expected if is_correct else "echo intento"
                    command_trace = [answer]
                    if item.get("id") == "shell_shadow_hashes":
                        extra_text = "hashcat"

                distro_expected = DISTRO_ROTATION[idx % len(DISTRO_ROTATION)]["name"]
                distro_guess = distro_expected if random.random() < 0.55 else "No se"

                if is_correct:
                    score += 1

                responses.append(
                    (
                        token,
                        idx,
                        item.get("id", ""),
                        item.get("type", ""),
                        item.get("prompt", ""),
                        answer,
                        distro_guess,
                        json.dumps(command_trace),
                        extra_text,
                        1 if is_correct else 0,
                        expected,
                        iso(submitted_at),
                    )
                )
                timings.append((token, idx, float(seconds), None))

                attempts_rows.append(
                    (
                        token,
                        idx,
                        item.get("id", ""),
                        1,
                        answer,
                        1 if is_correct else 0,
                        iso(submitted_at - timedelta(seconds=2)),
                    )
                )
                if not is_correct and random.random() < 0.45:
                    second_ok = 1 if random.random() < 0.6 else 0
                    second_answer = expected if second_ok else f"{answer} --retry"
                    attempts_rows.append(
                        (
                            token,
                            idx,
                            item.get("id", ""),
                            2,
                            second_answer,
                            second_ok,
                            iso(submitted_at - timedelta(seconds=1)),
                        )
                    )

            finished = started + timedelta(seconds=elapsed + random.randint(12, 90))

            cur.execute(
                """
                INSERT INTO exam_sessions
                (session_token, student_name, student_email, started_at, finished_at, current_index, total_items, completed, score, exam_payload, resets_count, max_reached_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token,
                    p["name"],
                    p["email"],
                    iso(started),
                    iso(finished),
                    total,
                    total,
                    1,
                    score,
                    json.dumps(payload),
                    p["resets"],
                    max(0, total - 1),
                ),
            )
            cur.executemany(
                """
                INSERT INTO responses
                (session_token, item_index, item_id, item_type, prompt, user_answer, distro_guess, command_trace, extra_text, is_correct, expected, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                responses,
            )
            cur.executemany(
                """
                INSERT INTO question_timing
                (session_token, item_index, seconds_spent, last_entered_at)
                VALUES (?, ?, ?, ?)
                """,
                timings,
            )
            cur.executemany(
                """
                INSERT INTO response_attempts
                (session_token, item_index, item_id, attempt_no, user_answer, is_correct, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                attempts_rows,
            )

            inserted_sessions += 1

    conn.commit()
    print("seed_done")
    print("sessions_inserted", inserted_sessions)
    for p in PROFILES:
        cnt = conn.execute("SELECT COUNT(*) FROM exam_sessions WHERE student_email = ?", (p["email"],)).fetchone()[0]
        print(p["email"], cnt)


def main() -> None:
    db_path = ROOT / "instance" / "curso_linux.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    clear_all_data(conn)
    seed(conn)
    conn.close()


if __name__ == "__main__":
    main()
