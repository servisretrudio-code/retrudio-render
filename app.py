import hashlib
import hmac
import json
import logging
from decimal import Decimal, InvalidOperation
from urllib.parse import urlencode
import re
import secrets
from datetime import datetime, timedelta
from types import SimpleNamespace
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, send_from_directory, session, url_for)
from markupsafe import Markup
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import CppLexer
from werkzeug.security import check_password_hash, generate_password_hash

import catalog
import config
import mailer
from database import close_db, get_db, init_db, utcnow
from i18n import translate

if config.APP_ENV == "production" and (config.SECRET_KEY in ("dev-only-change-me", "замените-на-длинную-случайную-строку") or len(config.SECRET_KEY) < 24):
    raise SystemExit("Задайте уникальный SECRET_KEY (24+ символов) в .env перед запуском в production")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.APP_ENV == "production",
    MAX_CONTENT_LENGTH=1024 * 1024,
)
app.teardown_appcontext(close_db)
init_db()

# CSS подсветки синтаксиса генерируется один раз
try:
    (config.BASE_DIR / "static" / "pygments.css").write_text(
        HtmlFormatter(style="monokai").get_style_defs(".hl"), encoding="utf-8")
except OSError:
    pass  # read-only файловая система: положите pygments.css в static/ заранее

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- helpers ----------
def ban_info(user):
    """Данные о бане или None, если пользователь не забанен.
    Бан выставляет Telegram-бот в таблице users. Статусы бота:
      'active'      — всё в порядке
      'banned'      — временный бан (дата окончания в banned_until)
      'perm_banned' — бан навсегда
    Причина бана лежит в ban_reason."""
    if not user:
        return None
    keys = user.keys()
    status = user["status"] if "status" in keys else None
    reason = (user["ban_reason"] if "ban_reason" in keys else None) or ""
    if status == "perm_banned":
        return {"until": None, "reason": reason}
    if status == "banned":
        until = user["banned_until"] if "banned_until" in keys else None
        if not until:
            return {"until": None, "reason": reason}
        try:
            if datetime.fromisoformat(until) <= utcnow():
                return None          # срок бана истёк
        except ValueError:
            pass                     # непонятная дата — на всякий случай считаем бан действующим
        return {"until": until, "reason": reason}
    return None


def ban_message(b, lang):
    ru = lang == "ru"
    if b["until"]:
        when = b["until"][:16].replace("T", " ")
        text = (f"Ваш аккаунт заблокирован до {when} (UTC)." if ru
                else f"Your account is banned until {when} (UTC).")
    else:
        text = "Ваш аккаунт заблокирован навсегда." if ru else "Your account is permanently banned."
    if b["reason"]:
        text += (" Причина: " if ru else " Reason: ") + b["reason"]
    return text


@app.before_request
def before():
    if request.args.get("lang") in config.LANGS:
        session["lang"] = request.args["lang"]
    g.lang = session.get("lang", "ru")
    g.user = None
    if session.get("uid"):
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
        b = ban_info(g.user)
        if b:  # забаненного сразу выкидываем из аккаунта
            g.user = None
            session.pop("uid", None)
            flash(ban_message(b, g.lang))
            if request.endpoint != "static" and not request.path.startswith("/api/"):
                return redirect(url_for("login"))
    if request.method in ("POST", "PUT", "DELETE") and request.endpoint not in ("payment_notify", "payment_success", "payment_fail"):
        token = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, session.get("csrf", "")):
            abort(400, "CSRF")


def has_subscription(user):
    if user and user["is_admin"]:      # администраторам открыты все платные проекты
        return True
    if not user or not user["subscription_until"]:
        return False
    return datetime.fromisoformat(user["subscription_until"]) >= utcnow()


def can_access(item):
    return item["free"] or has_subscription(g.user)


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            flash(translate("need_login", g.lang))
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return dict(
        t=lambda k: translate(k, g.lang), lang=g.lang, user=g.user,
        csrf=session["csrf"], PROJECT_NAME=config.PROJECT_NAME, LANGS=config.LANGS,
        loc=lambda v: catalog.loc(v, g.lang), CATEGORIES=catalog.CATEGORIES,
        has_sub=has_subscription(g.user),
        cfg=SimpleNamespace(CONTACT_EMAIL=config.CONTACT_EMAIL, DONATE_URL=config.DONATE_URL,
                            FREEKASSA_READY=config.FREEKASSA_READY, SUBSCRIPTION_PRICE=config.SUBSCRIPTION_PRICE,
                            SUBSCRIPTION_CURRENCY=config.SUBSCRIPTION_CURRENCY,
                            SUBSCRIPTION_DAYS=config.SUBSCRIPTION_DAYS),   # только безопасные значения, без секретов
    )


def highlight_code(code):
    return Markup(highlight(code, CppLexer(), HtmlFormatter(cssclass="hl")))


def safe_next(url):
    return url if url and url.startswith("/") and not url.startswith(("//", "/\\")) else url_for("index")


# ---------- pages ----------
@app.route("/")
def index():
    items = catalog.search(g.lang)
    db = get_db()
    rows = db.execute("SELECT project_id, COUNT(*) c FROM favorites GROUP BY project_id "
                      "ORDER BY c DESC LIMIT 3").fetchall()
    popular = [(catalog.get(r["project_id"]), r["c"]) for r in rows if catalog.get(r["project_id"])]
    return render_template("index.html", latest=items[:6], popular=popular, total=len(items))


@app.route("/projects")
def projects():
    a = request.args
    items = catalog.search(g.lang, a.get("q", ""), a.get("board", ""), a.get("category", ""),
                           a.get("difficulty", ""), a.get("access", ""), a.get("component", ""),
                           a.get("sort", "new"))
    page = max(1, request.args.get("page", 1, type=int))
    pages = max(1, -(-len(items) // config.PER_PAGE))
    page = min(page, pages)
    chunk = items[(page - 1) * config.PER_PAGE: page * config.PER_PAGE]
    args = {k: v for k, v in a.items() if k != "page" and v}
    return render_template("catalog.html", items=chunk, page=page, pages=pages, args=args,
                           boards=catalog.boards(), total=len(items))


@app.route("/library")
def library():
    a = request.args
    items = catalog.search(g.lang, a.get("q", ""), a.get("board", ""), "", a.get("difficulty", ""),
                           "", a.get("component", ""), a.get("sort", "new"), need_code=True)
    return render_template("library.html", items=items, boards=catalog.boards(), args=a)


@app.route("/project/<int:pid>")
def project(pid):
    item = catalog.get(pid)
    if not item:
        abort(404)
    ok = can_access(item)
    db = get_db()
    comments = db.execute("SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id "
                          "WHERE project_id=? ORDER BY c.id DESC", (pid,)).fetchall()
    rated = [c["rating"] for c in comments if c["rating"]]
    avg = round(sum(rated) / len(rated), 1) if rated else None
    is_fav = bool(g.user and db.execute("SELECT 1 FROM favorites WHERE user_id=? AND project_id=?",
                                        (g.user["id"], pid)).fetchone())
    return render_template("project.html", p=item, ok=ok, comments=comments, avg=avg,
                           n_rated=len(rated), is_fav=is_fav, similar=catalog.similar(item),
                           code_html=highlight_code(item["code"]) if ok and item["code"] else "")


@app.route("/project/<int:pid>/download")
def download(pid):
    item = catalog.get(pid)
    if not item or not item["code"]:
        abort(404)
    if not can_access(item):
        abort(403)
    fname = re.sub(r"[^A-Za-z0-9_-]", "_", item["code_file"].rsplit(".", 1)[0]) or f"project_{pid}"
    # Arduino IDE требует, чтобы папка скетча называлась так же, как .ino
    return Response(item["code"], mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.ino"'})


@app.route("/scheme-image/<int:pid>")
def scheme_image(pid):
    if not catalog.get(pid):
        abort(404)
    return send_from_directory(config.SCHEMES_DIR, f"{pid}.png")


@app.route("/project/<int:pid>/favorite", methods=["POST"])
@login_required
def favorite(pid):
    if not catalog.get(pid):
        abort(404)
    db = get_db()
    cur = db.execute("DELETE FROM favorites WHERE user_id=? AND project_id=?", (g.user["id"], pid))
    if cur.rowcount == 0:
        db.execute("INSERT INTO favorites VALUES(?,?)", (g.user["id"], pid))
    db.commit()
    return redirect(url_for("project", pid=pid))


@app.route("/project/<int:pid>/comment", methods=["POST"])
@login_required
def comment(pid):
    if not catalog.get(pid):
        abort(404)
    body = request.form.get("body", "").strip()[:2000]
    rating = request.form.get("rating", type=int)
    if rating not in (1, 2, 3, 4, 5):
        rating = None
    if body:
        db = get_db()
        db.execute("INSERT INTO comments(project_id,user_id,body,rating) VALUES(?,?,?,?)",
                   (pid, g.user["id"], body, rating))
        db.commit()
    return redirect(url_for("project", pid=pid) + "#comments")


@app.route("/favorites")
@login_required
def favorites():
    rows = get_db().execute("SELECT project_id FROM favorites WHERE user_id=?", (g.user["id"],)).fetchall()
    items = [catalog.get(r["project_id"]) for r in rows if catalog.get(r["project_id"])]
    return render_template("favorites.html", items=items)


@app.route("/community")
def community():
    db = get_db()
    designs = db.execute("SELECT d.id,d.title,d.updated,u.name FROM designs d JOIN users u ON u.id=d.user_id "
                         "WHERE d.public=1 ORDER BY d.updated DESC LIMIT 30").fetchall()
    comments = db.execute("SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id "
                          "ORDER BY c.id DESC LIMIT 10").fetchall()
    return render_template("community.html", designs=designs, comments=comments, catalog=catalog)


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/donate")
def donate():
    return render_template("donate.html")


# ---------- auth ----------
def _hash_code(email, code):
    return hmac.new(config.SECRET_KEY.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def _issue_code(email, name):
    """Создаёт код, шлёт письмо. Возвращает ключ сообщения об ошибке или None."""
    code = f"{secrets.randbelow(10**6):06d}"
    if config.SC5MAILS_READY:
        if not mailer.send_code(email, code, name, request.remote_addr or "-", request.user_agent.platform or request.user_agent.string or "-"):
            return "verify_fail"
    elif config.APP_ENV == "production":
        return "verify_off"
    else:       # разработка без ключей сервиса: код печатается в консоль сервера
        app.logger.warning("DEV: код подтверждения для %s: %s", email, code)
    get_db().execute("UPDATE pending_registrations SET code_hash=?, expires=?, attempts=0, last_sent=? WHERE email=?",
                     (_hash_code(email, code), (utcnow() + timedelta(minutes=config.CODE_TTL_MIN)).isoformat(),
                      utcnow().isoformat(), email))
    get_db().commit()
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()[:60]
        pw = request.form.get("password", "")
        if not EMAIL_RE.match(email) or not name or len(pw) < 8:
            flash(translate("invalid_form", g.lang))
        else:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                flash(translate("email_taken", g.lang))
            else:
                old = db.execute("SELECT last_sent FROM pending_registrations WHERE email=?", (email,)).fetchone()
                if old and (utcnow() - datetime.fromisoformat(old["last_sent"])).total_seconds() < config.CODE_RESEND_SEC:
                    flash(translate("verify_wait", g.lang))
                    return render_template("auth.html", mode="register")
                db.execute("INSERT OR REPLACE INTO pending_registrations(email,name,password_hash,code_hash,expires,attempts,last_sent)"
                           " VALUES(?,?,?,?,?,0,?)", (email, name, generate_password_hash(pw), "", utcnow().isoformat(),
                                                    (utcnow() - timedelta(days=1)).isoformat()))
                db.commit()
                err = _issue_code(email, name)
                if err:
                    db.execute("DELETE FROM pending_registrations WHERE email=?", (email,)); db.commit()
                    flash(translate(err, g.lang))
                else:
                    session["pending_email"] = email
                    return redirect(url_for("verify"))
    return render_template("auth.html", mode="register")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email")
    db = get_db()
    row = db.execute("SELECT * FROM pending_registrations WHERE email=?", (email,)).fetchone() if email else None
    if not row:
        return redirect(url_for("register"))
    if request.method == "POST":
        code = re.sub(r"\D", "", request.form.get("code", ""))
        if datetime.fromisoformat(row["expires"]) < utcnow() or row["attempts"] >= config.CODE_MAX_ATTEMPTS:
            db.execute("DELETE FROM pending_registrations WHERE email=?", (email,)); db.commit()
            session.pop("pending_email", None)
            flash(translate("verify_expired", g.lang))
            return redirect(url_for("register"))
        if not hmac.compare_digest(_hash_code(email, code), row["code_hash"]):
            db.execute("UPDATE pending_registrations SET attempts=attempts+1 WHERE email=?", (email,)); db.commit()
            flash(translate("verify_bad", g.lang))
        else:
            if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                flash(translate("email_taken", g.lang)); return redirect(url_for("register"))
            cur = db.execute("INSERT INTO users(email,name,password_hash) VALUES(?,?,?)",
                             (email, row["name"], row["password_hash"]))
            db.execute("DELETE FROM pending_registrations WHERE email=?", (email,)); db.commit()
            lang = session.get("lang")
            session.clear(); session["uid"] = cur.lastrowid
            if lang: session["lang"] = lang
            return redirect(url_for("index"))
    return render_template("verify.html", email=email)


@app.route("/verify/resend", methods=["POST"])
def verify_resend():
    email = session.get("pending_email")
    row = get_db().execute("SELECT last_sent, name FROM pending_registrations WHERE email=?", (email,)).fetchone() if email else None
    if not row:
        return redirect(url_for("register"))
    if (utcnow() - datetime.fromisoformat(row["last_sent"])).total_seconds() < config.CODE_RESEND_SEC:
        flash(translate("verify_wait", g.lang))
    else:
        err = _issue_code(email, row["name"])
        flash(translate(err or "verify_resent", g.lang))
    return redirect(url_for("verify"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        row = get_db().execute("SELECT * FROM users WHERE email=? OR username=?", (email, email)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            b = ban_info(row)
            if b:  # пароль верный, но аккаунт в бане — в аккаунт не пускаем
                flash(ban_message(b, g.lang))
                return render_template("auth.html", mode="login")
            lang = session.get("lang")
            session.clear()
            session["uid"] = row["id"]
            if lang:
                session["lang"] = lang
            return redirect(safe_next(request.args.get("next")))
        flash(translate("bad_credentials", g.lang))
    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------- builder ----------
@app.route("/builder")
def builder():
    return render_template("builder.html", design_id=None)


@app.route("/design/<int:did>")
def design_view(did):
    row = get_db().execute("SELECT * FROM designs WHERE id=?", (did,)).fetchone()
    if not row or (not row["public"] and not (g.user and g.user["id"] == row["user_id"])):
        abort(404)
    return render_template("builder.html", design_id=did)


@app.route("/api/designs", methods=["GET", "POST"])
def api_designs():
    if not g.user:
        return jsonify(error="auth"), 401
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id,title,public,updated FROM designs WHERE user_id=? ORDER BY updated DESC",
                          (g.user["id"],)).fetchall()
        return jsonify([dict(r) for r in rows])
    body = request.get_json(silent=True) or {}
    title = str(body.get("title", "")).strip()[:100]
    data = body.get("data")
    if not title or not isinstance(data, dict) or len(json.dumps(data)) > 500_000:
        return jsonify(error="invalid"), 400
    public = 1 if body.get("public") else 0
    did = body.get("id")
    now = utcnow().isoformat(timespec="seconds")
    if did and db.execute("SELECT 1 FROM designs WHERE id=? AND user_id=?", (did, g.user["id"])).fetchone():
        db.execute("UPDATE designs SET title=?,data=?,public=?,updated=? WHERE id=?",
                   (title, json.dumps(data), public, now, did))
    else:
        cur = db.execute("INSERT INTO designs(user_id,title,data,public,updated) VALUES(?,?,?,?,?)",
                         (g.user["id"], title, json.dumps(data), public, now))
        did = cur.lastrowid
    db.commit()
    return jsonify(id=did)


@app.route("/api/designs/<int:did>", methods=["GET", "DELETE"])
def api_design(did):
    db = get_db()
    row = db.execute("SELECT * FROM designs WHERE id=?", (did,)).fetchone()
    mine = bool(row and g.user and row["user_id"] == g.user["id"])
    if not row or (not row["public"] and not mine):
        return jsonify(error="not_found"), 404
    if request.method == "DELETE":
        if not mine:
            return jsonify(error="forbidden"), 403
        db.execute("DELETE FROM designs WHERE id=?", (did,))
        db.commit()
        return jsonify(ok=True)
    return jsonify(id=row["id"], title=row["title"], public=row["public"],
                   mine=mine, data=json.loads(row["data"]))


# ---------- payments (FreeKassa) ----------
def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _client_ip():
    # За nginx включите TRUST_PROXY=1 и передавайте X-Real-IP (как в документации FreeKassa)
    if config.TRUST_PROXY and request.headers.get("X-Real-IP"):
        return request.headers["X-Real-IP"].strip()
    return request.remote_addr


@app.route("/pay/subscribe", methods=["POST"])
@login_required
def pay_subscribe():
    if not config.FREEKASSA_READY:
        abort(404)
    db = get_db()
    cur = db.execute("INSERT INTO payments(user_id,amount,currency,days) VALUES(?,?,?,?)",
                     (g.user["id"], config.SUBSCRIPTION_PRICE, config.SUBSCRIPTION_CURRENCY,
                      config.SUBSCRIPTION_DAYS))
    db.commit()
    order_id = str(cur.lastrowid)
    # подпись формы: shop_id:сумма:секретное слово 1:валюта:номер заказа
    sign = _md5(":".join([config.FREEKASSA_SHOP_ID, config.SUBSCRIPTION_PRICE,
                          config.FREEKASSA_SECRET1, config.SUBSCRIPTION_CURRENCY, order_id]))
    q = urlencode({"m": config.FREEKASSA_SHOP_ID, "oa": config.SUBSCRIPTION_PRICE,
                   "currency": config.SUBSCRIPTION_CURRENCY, "o": order_id, "s": sign,
                   "em": g.user["email"], "lang": g.lang if g.lang in ("ru", "en") else "ru"})
    return redirect(config.FREEKASSA_PAY_URL + "?" + q)


@app.route("/payment/notify", methods=["GET", "POST"])
def payment_notify():
    """URL оповещения. Подписку выдаёт ТОЛЬКО он, после проверки подписи и суммы."""
    v = request.values
    log = app.logger
    if config.FREEKASSA_ALLOWED_IPS and _client_ip() not in config.FREEKASSA_ALLOWED_IPS:
        log.warning("FreeKassa notify: IP %s не в списке FREEKASSA_ALLOWED_IPS (за nginx нужен TRUST_PROXY=1)", _client_ip())
        return "hacking attempt", 403
    if not config.FREEKASSA_READY:
        return "not configured", 503
    amount, order_id, merchant_id = v.get("AMOUNT", ""), v.get("MERCHANT_ORDER_ID", ""), v.get("MERCHANT_ID", "")
    # подпись оповещения: shop_id:AMOUNT:секретное слово 2:MERCHANT_ORDER_ID
    expected = _md5(":".join([config.FREEKASSA_SHOP_ID, amount, config.FREEKASSA_SECRET2, order_id]))
    if merchant_id != config.FREEKASSA_SHOP_ID or not hmac.compare_digest(expected, v.get("SIGN", "").lower()):
        log.warning("FreeKassa notify: неверная подпись (заказ %s)", order_id)
        return "wrong sign", 400
    db = get_db()
    row = db.execute("SELECT * FROM payments WHERE id=?", (order_id,)).fetchone() if order_id.isdigit() else None
    if not row:
        return "order not found", 404
    try:
        if Decimal(amount) != Decimal(row["amount"]):
            log.warning("FreeKassa notify: сумма %s != %s (заказ %s)", amount, row["amount"], order_id)
            return "wrong amount", 400
    except InvalidOperation:
        return "wrong amount", 400
    # Одна транзакция: статус заказа и подписка меняются вместе, повтор/гонка не выдаст подписку дважды
    cur = db.execute("UPDATE payments SET status='paid', fk_intid=?, paid_at=? WHERE id=? AND status!='paid'",
                     (v.get("intid"), utcnow().isoformat(timespec="seconds"), row["id"]))
    if cur.rowcount == 1:
        u = db.execute("SELECT subscription_until FROM users WHERE id=?", (row["user_id"],)).fetchone()
        base = max(datetime.fromisoformat(u["subscription_until"]), utcnow()) if u and u["subscription_until"] else utcnow()
        db.execute("UPDATE users SET subscription_until=? WHERE id=?",
                   ((base + timedelta(days=row["days"])).isoformat(), row["user_id"]))
    db.commit()
    return "YES"


@app.route("/payment/success", methods=["GET", "POST"])
def payment_success():
    # Здесь подписка НЕ выдаётся — только сообщение. Выдача идёт через /payment/notify.
    return render_template("payment_result.html", ok=True)


@app.route("/payment/fail", methods=["GET", "POST"])
def payment_fail():
    return render_template("payment_result.html", ok=False)


@app.errorhandler(403)
@app.errorhandler(404)
def err(e):
    return render_template("error.html", code=e.code), e.code


if __name__ == "__main__":
    # Render автоматически передает порт через переменную окружения PORT
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
