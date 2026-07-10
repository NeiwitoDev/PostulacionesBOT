"""Servidor web de Postulaciones: login con Discord, Home, Admin y Gestión."""

import os
import secrets as pysecrets
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_wtf import CSRFProtect

from web import db
from web import discord_api as dapi

SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    raise RuntimeError(
        "Falta la variable de entorno SESSION_SECRET. Configúrala como secreto antes de iniciar la web."
    )

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("REPLIT_DEV_DOMAIN")) or os.environ.get("REPLIT_DEPLOYMENT") == "1",
)
csrf = CSRFProtect(app)

INITIAL_ADMIN_USER_ID = os.environ.get("INITIAL_ADMIN_USER_ID")


def get_redirect_uri() -> str:
    domain = os.environ.get("REPLIT_DEV_DOMAIN") or request.host
    scheme = "https" if os.environ.get("REPLIT_DEV_DOMAIN") else request.scheme
    return f"{scheme}://{domain}/callback"


def current_user() -> dict | None:
    uid = session.get("discord_id")
    if not uid:
        return None
    return db.get_user(uid)


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def gestion_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not (user["is_admin"] or user["is_gestion"]):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

@app.route("/login")
def login():
    if current_user():
        return redirect(url_for("home"))
    state = pysecrets.token_urlsafe(16)
    session["oauth_state"] = state
    params = {
        "client_id": dapi.CLIENT_ID,
        "redirect_uri": get_redirect_uri(),
        "response_type": "code",
        "scope": "identify",
        "state": state,
        "prompt": "consent",
    }
    from urllib.parse import urlencode
    return redirect(f"https://discord.com/oauth2/authorize?{urlencode(params)}")


@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        flash("Inicio de sesión cancelado.", "error")
        return redirect(url_for("landing"))

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.get("oauth_state"):
        abort(400)

    try:
        token_data = dapi.exchange_code(code, get_redirect_uri())
        identity = dapi.get_user_identity(token_data["access_token"])
    except Exception:
        flash("No se pudo completar el inicio de sesión con Discord.", "error")
        return redirect(url_for("landing"))

    discord_id = int(identity["id"])
    username = identity.get("global_name") or identity.get("username")
    avatar = identity.get("avatar")

    has_role = dapi.user_has_admin_role(discord_id)
    is_initial_admin = INITIAL_ADMIN_USER_ID is not None and str(discord_id) == str(INITIAL_ADMIN_USER_ID)

    db.upsert_login_user(discord_id, username, avatar, has_role, is_initial_admin)

    session["discord_id"] = discord_id
    session.pop("oauth_state", None)
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ---------------------------------------------------------------------------
# Páginas públicas / Home
# ---------------------------------------------------------------------------

@app.route("/")
def landing():
    if current_user():
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/home")
@login_required
def home():
    forms = db.list_forms(status="open")
    user = current_user()
    applied_ids = set()
    for f in forms:
        existing = db.get_application_for_user(f["id"], user["discord_id"])
        if existing:
            applied_ids.add(f["id"])
    return render_template("home.html", forms=forms, applied_ids=applied_ids)


@app.route("/apply/<int:form_id>", methods=["GET", "POST"])
@login_required
def apply(form_id):
    form = db.get_form(form_id)
    if not form or form["status"] != "open":
        abort(404)
    user = current_user()
    existing = db.get_application_for_user(form_id, user["discord_id"])
    if existing:
        flash("Ya te postulaste a esta postulación.", "error")
        return redirect(url_for("home"))

    questions = form["questions"] or []

    if request.method == "POST":
        answers = []
        for i, question in enumerate(questions):
            value = request.form.get(f"q{i}", "").strip()
            if not value:
                flash("Debes responder todas las preguntas.", "error")
                return render_template("apply.html", form=form, questions=questions)
            answers.append({"question": question, "answer": value})
        db.create_application(form_id, user["discord_id"], user["username"], answers)
        flash("¡Tu postulación fue enviada correctamente!", "success")
        return redirect(url_for("home"))

    return render_template("apply.html", form=form, questions=questions)


# ---------------------------------------------------------------------------
# Panel de Administración
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin():
    users = db.list_users()
    forms = db.list_forms()
    return render_template("admin.html", users=users, forms=forms)


@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_add_user():
    raw_id = request.form.get("discord_id", "").strip()
    if not raw_id.isdigit():
        flash("ID de Discord inválido.", "error")
        return redirect(url_for("admin"))
    discord_id = int(raw_id)
    grant_admin = request.form.get("grant_admin") == "on"
    grant_gestion = request.form.get("grant_gestion") == "on"

    public_user = dapi.fetch_public_user(discord_id)
    username = public_user.get("username") if public_user else f"Usuario {discord_id}"

    db.add_manual_user(discord_id, username, grant_admin, grant_gestion)
    flash(f"Permisos actualizados para {username}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:discord_id>/toggle/<field>", methods=["POST"])
@admin_required
def admin_toggle_user(discord_id, field):
    if field not in ("is_admin", "is_gestion"):
        abort(400)
    user = db.get_user(discord_id)
    if not user:
        abort(404)
    if discord_id == current_user()["discord_id"] and field == "is_admin" and user["is_admin"]:
        flash("No puedes quitarte tu propio permiso de administrador.", "error")
        return redirect(url_for("admin"))
    db.set_user_role(discord_id, field, not user[field])
    return redirect(url_for("admin"))


@app.route("/admin/forms/create", methods=["POST"])
@admin_required
def admin_create_form():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    raw_questions = request.form.get("questions", "")
    questions = [q.strip() for q in raw_questions.splitlines() if q.strip()]

    if not title or not questions:
        flash("La postulación necesita un título y al menos una pregunta.", "error")
        return redirect(url_for("admin"))

    db.create_form(title, description, questions, current_user()["discord_id"])
    flash("Postulación creada correctamente.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/forms/<int:form_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_form(form_id):
    form = db.get_form(form_id)
    if not form:
        abort(404)
    new_status = "closed" if form["status"] == "open" else "open"
    db.set_form_status(form_id, new_status)
    return redirect(url_for("admin"))


@app.route("/admin/forms/<int:form_id>/delete", methods=["POST"])
@admin_required
def admin_delete_form(form_id):
    db.delete_form(form_id)
    flash("Postulación eliminada.", "success")
    return redirect(url_for("admin"))


# ---------------------------------------------------------------------------
# Panel de Gestión
# ---------------------------------------------------------------------------

@app.route("/gestion")
@gestion_required
def gestion():
    applications = db.list_applications()
    return render_template("gestion.html", applications=applications)


@app.route("/gestion/app/<int:app_id>/notify", methods=["POST"])
@gestion_required
def gestion_notify(app_id):
    application = db.get_application(app_id)
    if not application:
        abort(404)
    dm_sent = dapi.send_dm(
        application["user_id"],
        content=(
            f"👀 Tu postulación a **{application['form_title']}** está siendo "
            "revisada por el equipo de gestión. Te avisaremos en cuanto haya una decisión."
        ),
    )
    db.update_application_status(app_id, "in_review")
    if dm_sent:
        flash("Se avisó al usuario que su postulación está en revisión.", "success")
    else:
        flash("El estado se actualizó, pero no se pudo enviar el MD (el usuario puede tener los mensajes cerrados).", "error")
    return redirect(url_for("gestion"))


@app.route("/gestion/app/<int:app_id>/approve", methods=["POST"])
@gestion_required
def gestion_approve(app_id):
    application = db.get_application(app_id)
    if not application:
        abort(404)
    note = request.form.get("note", "").strip()
    score = request.form.get("score", "").strip()
    reviewer = current_user()

    embed = {
        "title": "✅ ¡Postulación aprobada!",
        "description": (
            f"Tu postulación a **{application['form_title']}** fue **aprobada**.\n\n"
            "Pasas a la **Fase 2: Entrevista vía llamada de voz (VC)**. "
            "El equipo de gestión se pondrá en contacto contigo para coordinar el horario."
        ),
        "color": 0x2ECC71,
        "fields": (
            [{"name": "Nota final", "value": score, "inline": True}] if score else []
        ) + [{"name": "Revisado por", "value": reviewer["username"], "inline": True}],
    }
    if note:
        embed["fields"].append({"name": "Comentario", "value": note, "inline": False})

    dm_sent = dapi.send_dm(application["user_id"], embed=embed)
    db.update_application_status(
        app_id, "approved",
        reviewer_id=reviewer["discord_id"], reviewer_name=reviewer["username"],
        review_note=note or None, final_score=score or None,
    )
    if dm_sent:
        flash("Postulación aprobada y notificada al usuario.", "success")
    else:
        flash("Postulación aprobada, pero no se pudo enviar el MD (el usuario puede tener los mensajes cerrados).", "error")
    return redirect(url_for("gestion"))


@app.route("/gestion/app/<int:app_id>/reject", methods=["POST"])
@gestion_required
def gestion_reject(app_id):
    application = db.get_application(app_id)
    if not application:
        abort(404)
    reason = request.form.get("reason", "").strip()
    if not reason:
        flash("Debes indicar un motivo de rechazo.", "error")
        return redirect(url_for("gestion"))
    reviewer = current_user()

    embed = {
        "title": "❌ Postulación rechazada",
        "description": (
            f"Tu postulación a **{application['form_title']}** no fue aprobada en esta ocasión."
        ),
        "color": 0xE74C3C,
        "fields": [
            {"name": "Motivo", "value": reason, "inline": False},
            {"name": "Revisado por", "value": reviewer["username"], "inline": True},
        ],
    }

    dm_sent = dapi.send_dm(application["user_id"], embed=embed)
    db.update_application_status(
        app_id, "rejected",
        reviewer_id=reviewer["discord_id"], reviewer_name=reviewer["username"],
        review_note=reason,
    )
    if dm_sent:
        flash("Postulación rechazada y notificada al usuario.", "success")
    else:
        flash("Postulación rechazada, pero no se pudo enviar el MD (el usuario puede tener los mensajes cerrados).", "error")
    return redirect(url_for("gestion"))


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message="Solicitud inválida o expirada. Intenta de nuevo."), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="No tienes permiso para ver esta página."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Página no encontrada."), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
