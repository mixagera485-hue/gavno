#!/usr/bin/env python3
"""
FREEZ CLIENT — простой Python backend + SQLite.

Файлы app.py и index.html должны лежать в одной папке.

Запуск:
    python app.py

Render / Railway:
    PORT=10000 python app.py

Переменные:
    PORT — порт сервера (по умолчанию 8080)
    FREEZ_DB — путь к SQLite (по умолчанию ./freez.db)
    FREEZ_ADMIN_NICK — ник администратора (по умолчанию migi)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SITE_ROOT = ROOT
DB_PATH = Path(os.environ.get("FREEZ_DB", str(ROOT / "freez.db")))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
ADMIN_NICK = os.environ.get("FREEZ_ADMIN_NICK", "migi").strip().lower()
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PBKDF2_ITERATIONS = 210_000


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            nick TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            subscription INTEGER NOT NULL DEFAULT 0,
            subscription_until INTEGER,
            blocked INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            duration TEXT NOT NULL,
            target TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at REAL NOT NULL,
            used_by TEXT,
            used_at REAL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            uid INTEGER NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> tuple[bool, bool]:
    """Returns (valid, needs_upgrade). Supports the old freez_v1 SHA-256 format."""
    if not stored:
        return False, False

    if stored.startswith("pbkdf2$"):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$", 3)
            iterations = int(iterations)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, iterations
            )
            return hmac.compare_digest(actual, expected), False
        except (ValueError, TypeError):
            return False, False

    # Legacy hash used by the previous version.
    legacy = hashlib.sha256(("freez_v1" + password).encode("utf-8")).hexdigest()
    if hmac.compare_digest(legacy, stored):
        return True, True
    return False, False


def user_public(row: sqlite3.Row) -> dict:
    until = row["subscription_until"]
    active = bool(row["subscription"])
    if until is not None and int(until) <= int(time.time() * 1000):
        active = False
    return {
        "uid": int(row["uid"]),
        "nick": row["nick"],
        "email": row["email"],
        "role": row["role"],
        "subscription": active,
        "subscriptionUntil": until,
        "blocked": bool(row["blocked"]),
        "createdAt": row["created_at"],
    }


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type, x-session-token",
    )
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    try:
        length = int(handler.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        raw = handler.rfile.read(length)
        return json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, json.JSONDecodeError):
        return {}


def get_user_by_token(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    return conn.execute(
        """SELECT u.*
           FROM sessions s
           JOIN users u ON u.uid = s.uid
           WHERE s.token = ?""",
        (token,),
    ).fetchone()


def create_session(conn: sqlite3.Connection, uid: int) -> str:
    token = secrets.token_urlsafe(48)
    conn.execute(
        "INSERT INTO sessions(token, uid, created_at) VALUES (?, ?, ?)",
        (token, uid, time.time()),
    )
    conn.commit()
    return token


def is_admin_user(row: sqlite3.Row | None) -> bool:
    return bool(
        row
        and (
            row["role"] == "admin"
            or str(row["nick"]).strip().lower() == ADMIN_NICK
        )
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "FreezServer/2.0"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-session-token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/health":
            return json_response(
                self,
                200,
                {"ok": True, "db": str(DB_PATH), "server": "freez"},
            )

        if path in ("/", "/index.html"):
            return self._serve_file(SITE_ROOT / "index.html", "text/html; charset=utf-8")

        safe = path.lstrip("/")
        if ".." in safe.split("/"):
            return json_response(self, 400, {"message": "Bad path"})

        file_path = SITE_ROOT / safe
        if file_path.is_file():
            ctype = "application/octet-stream"
            if safe.endswith(".html"):
                ctype = "text/html; charset=utf-8"
            elif safe.endswith(".css"):
                ctype = "text/css; charset=utf-8"
            elif safe.endswith(".js"):
                ctype = "application/javascript; charset=utf-8"
            elif safe.endswith(".png"):
                ctype = "image/png"
            elif safe.endswith((".jpg", ".jpeg")):
                ctype = "image/jpeg"
            return self._serve_file(file_path, ctype)

        return json_response(self, 404, {"message": "Not found"})

    def _serve_file(self, file_path: Path, content_type: str) -> None:
        if not file_path.is_file():
            return json_response(self, 404, {"message": "Not found"})
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return json_response(self, 404, {"message": "Not found"})

        route = path[len("/api"):]
        body = read_json(self)
        conn = db()
        try:
            token = self.headers.get("x-session-token") or body.get("token")
            me = get_user_by_token(conn, token)
            self._route(conn, route, body, me, token)
        except sqlite3.IntegrityError:
            conn.rollback()
            json_response(self, 400, {"message": "Такие данные уже существуют."})
        except Exception as exc:
            conn.rollback()
            print("API ERROR:", repr(exc))
            json_response(self, 500, {"message": "Внутренняя ошибка сервера."})
        finally:
            conn.close()

    def _route(
        self,
        conn: sqlite3.Connection,
        route: str,
        body: dict,
        me: sqlite3.Row | None,
        token: str | None,
    ) -> None:
        if route == "/auth/register":
            return self._register(conn, body)
        if route == "/auth/login":
            return self._login(conn, body)
        if route == "/auth/logout":
            return self._logout(conn, token)
        if route == "/auth/me":
            if not me:
                return json_response(self, 401, {"message": "Не авторизован"})
            return json_response(
                self,
                200,
                {"user": user_public(me), "token": token},
            )
        if route == "/auth/change-password":
            return self._change_password(conn, me, body)
        if route == "/auth/change-email":
            return self._change_email(conn, me, body)

        if route == "/admin/users":
            return self._admin_users(conn, me)
        if route == "/admin/key":
            return self._admin_key(conn, me, body)
        if route == "/admin/reset-password":
            return self._admin_reset_password(conn, me, body)
        if route == "/admin/update-user":
            return self._admin_update_user(conn, me, body)

        if route == "/keys/redeem":
            return self._redeem(conn, me, body)

        return json_response(self, 404, {"message": "Unknown endpoint"})

    def _register(self, conn: sqlite3.Connection, body: dict) -> None:
        nick = str(body.get("nick") or "").strip()
        email = str(body.get("email") or "").strip().lower()
        password = str(body.get("password") or "")

        if len(nick) < 3:
            return json_response(self, 400, {"message": "Никнейм должен быть минимум 3 символа."})
        if len(nick) > 32:
            return json_response(self, 400, {"message": "Никнейм слишком длинный."})
        if not EMAIL_RE.match(email):
            return json_response(self, 400, {"message": "Введите корректную почту."})
        if len(password) < 8:
            return json_response(self, 400, {"message": "Пароль должен быть минимум 8 символов."})

        if conn.execute(
            "SELECT 1 FROM users WHERE nick = ? COLLATE NOCASE", (nick,)
        ).fetchone():
            return json_response(self, 400, {"message": "Такой никнейм уже зарегистрирован."})

        if conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone():
            return json_response(self, 400, {"message": "Эта почта уже используется."})

        role = "admin" if nick.lower() == ADMIN_NICK else "user"

        # UID выдаёт SQLite PRIMARY KEY AUTOINCREMENT — браузер его не вычисляет.
        cur = conn.execute(
            """INSERT INTO users
               (nick, email, password_hash, role, subscription, subscription_until, blocked, created_at)
               VALUES (?, ?, ?, ?, 0, NULL, 0, ?)""",
            (nick, email, hash_password(password), role, time.time()),
        )
        uid = int(cur.lastrowid)
        conn.commit()

        row = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        token = create_session(conn, uid)
        data = user_public(row)
        data["token"] = token
        return json_response(self, 200, data)

    def _login(self, conn: sqlite3.Connection, body: dict) -> None:
        nick = str(body.get("nick") or "").strip()
        password = str(body.get("password") or "")

        row = conn.execute(
            "SELECT * FROM users WHERE nick = ? COLLATE NOCASE", (nick,)
        ).fetchone()

        if not row:
            return json_response(self, 400, {"message": "Аккаунт не найден. Создайте аккаунт."})
        if row["blocked"]:
            return json_response(self, 403, {"message": "Аккаунт заблокирован."})

        valid, upgrade = verify_password(password, row["password_hash"])
        if not valid:
            return json_response(self, 400, {"message": "Неверный пароль."})

        if upgrade:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE uid = ?",
                (hash_password(password), row["uid"]),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE uid = ?", (row["uid"],)).fetchone()

        token = create_session(conn, int(row["uid"]))
        data = user_public(row)
        data["token"] = token
        return json_response(self, 200, data)

    def _logout(self, conn: sqlite3.Connection, token: str | None) -> None:
        if token:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        return json_response(self, 200, {"ok": True})

    def _change_password(self, conn, me, body) -> None:
        if not me:
            return json_response(self, 401, {"message": "Не авторизован"})

        current = str(body.get("currentPassword") or "")
        new = str(body.get("newPassword") or "")
        if len(new) < 8:
            return json_response(self, 400, {"message": "Новый пароль должен быть минимум 8 символов."})

        valid, _ = verify_password(current, me["password_hash"])
        if not valid:
            return json_response(self, 400, {"message": "Неверный текущий пароль."})

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE uid = ?",
            (hash_password(new), me["uid"]),
        )
        conn.commit()
        return json_response(self, 200, {"ok": True})

    def _change_email(self, conn, me, body) -> None:
        if not me:
            return json_response(self, 401, {"message": "Не авторизован"})

        email = str(body.get("email") or "").strip().lower()
        password = str(body.get("password") or "")

        if not EMAIL_RE.match(email):
            return json_response(self, 400, {"message": "Введите корректную почту."})

        valid, _ = verify_password(password, me["password_hash"])
        if not valid:
            return json_response(self, 400, {"message": "Неверный пароль."})

        taken = conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND uid != ?",
            (email, me["uid"]),
        ).fetchone()
        if taken:
            return json_response(self, 400, {"message": "Эта почта уже используется."})

        conn.execute("UPDATE users SET email = ? WHERE uid = ?", (email, me["uid"]))
        conn.commit()
        return json_response(self, 200, {"ok": True, "email": email})

    def _admin_users(self, conn, me) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})
        rows = conn.execute("SELECT * FROM users ORDER BY uid ASC").fetchall()
        return json_response(self, 200, {"users": [user_public(r) for r in rows]})

    def _admin_key(self, conn, me, body) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})

        key = str(body.get("key") or "").strip().upper()
        duration = str(body.get("duration") or "7")
        target = str(body.get("target") or "").strip()

        if not key:
            return json_response(self, 400, {"message": "Ключ не задан"})

        conn.execute(
            """INSERT INTO keys(key, duration, target, active, created_by, created_at)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (key, duration, target, me["nick"], time.time()),
        )
        conn.commit()
        return json_response(self, 200, {"ok": True, "key": key})

    def _admin_reset_password(self, conn, me, body) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})

        try:
            uid = int(body.get("uid") or 0)
        except (ValueError, TypeError):
            uid = 0

        user = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        if not user:
            return json_response(self, 404, {"message": "Пользователь не найден"})

        # Старый пароль невозможно и не нужно показывать: в БД хранится только хэш.
        # Вместо этого администратор получает новый временный пароль один раз.
        temp = secrets.token_urlsafe(10)
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE uid = ?",
            (hash_password(temp), uid),
        )
        conn.execute("DELETE FROM sessions WHERE uid = ?", (uid,))
        conn.commit()

        return json_response(
            self,
            200,
            {"ok": True, "tempPassword": temp, "uid": uid},
        )

    def _admin_update_user(self, conn, me, body) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})

        try:
            uid = int(body.get("uid") or 0)
        except (ValueError, TypeError):
            uid = 0

        user = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        if not user:
            return json_response(self, 404, {"message": "Пользователь не найден"})

        role = str(body.get("role") or user["role"]).strip().lower()
        if role not in {"user", "media", "admin"}:
            role = "user"

        blocked = 1 if bool(body.get("blocked")) else 0

        subscription = body.get("subscription")
        if subscription is None:
            subscription = bool(user["subscription"])
        subscription = 1 if bool(subscription) else 0

        until = body.get("subscriptionUntil", user["subscription_until"])
        if until in ("", None):
            until = None
        else:
            try:
                until = int(until)
            except (ValueError, TypeError):
                until = None

        conn.execute(
            """UPDATE users
               SET role = ?, blocked = ?, subscription = ?, subscription_until = ?
               WHERE uid = ?""",
            (role, blocked, subscription, until, uid),
        )
        conn.commit()

        row = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        return json_response(self, 200, {"ok": True, "user": user_public(row)})

    def _redeem(self, conn, me, body) -> None:
        if not me:
            return json_response(self, 401, {"message": "Сначала войдите в аккаунт."})

        raw = str(body.get("key") or "").strip().upper()
        if not raw:
            return json_response(self, 400, {"message": "Введите ключ."})

        # Атомарно блокируем использование ключа через транзакцию.
        conn.execute("BEGIN IMMEDIATE")
        item = conn.execute(
            "SELECT * FROM keys WHERE key = ? AND active = 1", (raw,)
        ).fetchone()

        if not item:
            conn.rollback()
            return json_response(self, 400, {"message": "Ключ не найден или уже использован."})

        target = str(item["target"] or "").strip().lower()
        if target and target not in (str(me["nick"]).lower(), str(me["uid"])):
            conn.rollback()
            return json_response(self, 400, {"message": "Этот ключ предназначен для другого пользователя."})

        duration = str(item["duration"])
        expires = None
        if duration != "forever":
            try:
                days = int(duration)
                expires = int((time.time() + days * 86400) * 1000)
            except ValueError:
                conn.rollback()
                return json_response(self, 400, {"message": "Неверный срок ключа."})

        conn.execute(
            "UPDATE users SET subscription = 1, subscription_until = ? WHERE uid = ?",
            (expires, me["uid"]),
        )
        cur = conn.execute(
            """UPDATE keys
               SET active = 0, used_by = ?, used_at = ?
               WHERE id = ? AND active = 1""",
            (me["nick"], time.time(), item["id"]),
        )
        if cur.rowcount != 1:
            conn.rollback()
            return json_response(self, 409, {"message": "Ключ уже используется."})

        conn.commit()
        return json_response(
            self,
            200,
            {
                "ok": True,
                "subscriptionUntil": expires,
                "message": "Ключ активирован",
            },
        )


def main() -> None:
    init_db()
    print("Freez server:", f"http://{HOST}:{PORT}")
    print("SQLite DB:", DB_PATH)
    print("Index:", SITE_ROOT / "index.html")
    print("Admin nick:", ADMIN_NICK)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
