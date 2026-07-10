"""Acceso a la base de datos PostgreSQL para la web de Postulaciones.

Usa una conexión nueva por operación (vía un pool sencillo) para evitar
problemas de hilos con el servidor de desarrollo de Flask.
"""

import os
import json
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL")


@contextmanager
def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _dictify(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def query(sql: str, params: tuple = ()) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if cur.description:
                return _dictify(cur)
            return []


def query_one(sql: str, params: tuple = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: tuple = ()) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)


# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------

def upsert_login_user(discord_id: int, username: str, avatar: str | None,
                       is_admin_from_role: bool, is_initial_admin: bool) -> dict:
    """Crea o actualiza un usuario al iniciar sesión.

    Nunca degrada permisos ya otorgados manualmente; sólo los eleva si el
    usuario tiene el rol de admin en Discord o es el admin inicial.
    """
    existing = query_one("SELECT * FROM users WHERE discord_id = %s", (discord_id,))
    grant_admin = is_admin_from_role or is_initial_admin
    if existing is None:
        execute(
            """
            INSERT INTO users (discord_id, username, avatar, is_admin, is_gestion)
            VALUES (%s, %s, %s, %s, FALSE)
            """,
            (discord_id, username, avatar, grant_admin),
        )
    else:
        new_admin = existing["is_admin"] or grant_admin
        execute(
            """
            UPDATE users SET username = %s, avatar = %s, is_admin = %s, updated_at = NOW()
            WHERE discord_id = %s
            """,
            (username, avatar, new_admin, discord_id),
        )
    return query_one("SELECT * FROM users WHERE discord_id = %s", (discord_id,))


def get_user(discord_id: int) -> dict | None:
    return query_one("SELECT * FROM users WHERE discord_id = %s", (discord_id,))


def list_users() -> list[dict]:
    return query("SELECT * FROM users ORDER BY created_at DESC")


def set_user_role(discord_id: int, field: str, value: bool) -> None:
    if field not in ("is_admin", "is_gestion"):
        raise ValueError("Campo de rol inválido")
    execute(f"UPDATE users SET {field} = %s, updated_at = NOW() WHERE discord_id = %s", (value, discord_id))


def add_manual_user(discord_id: int, username: str, is_admin: bool, is_gestion: bool) -> None:
    execute(
        """
        INSERT INTO users (discord_id, username, avatar, is_admin, is_gestion)
        VALUES (%s, %s, NULL, %s, %s)
        ON CONFLICT (discord_id) DO UPDATE
            SET is_admin = EXCLUDED.is_admin OR users.is_admin,
                is_gestion = EXCLUDED.is_gestion OR users.is_gestion,
                username = EXCLUDED.username,
                updated_at = NOW()
        """,
        (discord_id, username, is_admin, is_gestion),
    )


# ---------------------------------------------------------------------------
# Formularios (postulaciones)
# ---------------------------------------------------------------------------

def list_forms(status: str | None = None) -> list[dict]:
    if status:
        return query("SELECT * FROM forms WHERE status = %s ORDER BY created_at DESC", (status,))
    return query("SELECT * FROM forms ORDER BY created_at DESC")


def get_form(form_id: int) -> dict | None:
    return query_one("SELECT * FROM forms WHERE id = %s", (form_id,))


def create_form(title: str, description: str, questions: list[str], created_by: int) -> int:
    row = query_one(
        """
        INSERT INTO forms (title, description, questions, status, created_by)
        VALUES (%s, %s, %s, 'open', %s)
        RETURNING id
        """,
        (title, description, json.dumps(questions), created_by),
    )
    return row["id"]


def set_form_status(form_id: int, status: str) -> None:
    execute("UPDATE forms SET status = %s, updated_at = NOW() WHERE id = %s", (status, form_id))


def delete_form(form_id: int) -> None:
    execute("DELETE FROM forms WHERE id = %s", (form_id,))


# ---------------------------------------------------------------------------
# Postulaciones (applications)
# ---------------------------------------------------------------------------

def get_application_for_user(form_id: int, user_id: int) -> dict | None:
    return query_one("SELECT * FROM applications WHERE form_id = %s AND user_id = %s", (form_id, user_id))


def create_application(form_id: int, user_id: int, username: str, answers: list[dict]) -> int:
    row = query_one(
        """
        INSERT INTO applications (form_id, user_id, username, answers, status)
        VALUES (%s, %s, %s, %s, 'pending')
        RETURNING id
        """,
        (form_id, user_id, username, json.dumps(answers)),
    )
    return row["id"]


def list_applications(status: str | None = None) -> list[dict]:
    if status:
        return query(
            """
            SELECT a.*, f.title AS form_title FROM applications a
            JOIN forms f ON f.id = a.form_id
            WHERE a.status = %s
            ORDER BY a.created_at ASC
            """,
            (status,),
        )
    return query(
        """
        SELECT a.*, f.title AS form_title FROM applications a
        JOIN forms f ON f.id = a.form_id
        ORDER BY a.created_at ASC
        """
    )


def get_application(app_id: int) -> dict | None:
    return query_one(
        """
        SELECT a.*, f.title AS form_title FROM applications a
        JOIN forms f ON f.id = a.form_id
        WHERE a.id = %s
        """,
        (app_id,),
    )


def update_application_status(app_id: int, status: str, reviewer_id: int | None = None,
                               reviewer_name: str | None = None, review_note: str | None = None,
                               final_score: str | None = None) -> None:
    execute(
        """
        UPDATE applications
        SET status = %s,
            reviewer_id = COALESCE(%s, reviewer_id),
            reviewer_name = COALESCE(%s, reviewer_name),
            review_note = COALESCE(%s, review_note),
            final_score = COALESCE(%s, final_score),
            updated_at = NOW()
        WHERE id = %s
        """,
        (status, reviewer_id, reviewer_name, review_note, final_score, app_id),
    )
