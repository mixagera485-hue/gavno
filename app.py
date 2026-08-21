#!/usr/bin/env python3
"""
Freez Client — backend + SQLite.
Раздаёт сайт и API. Один файл, без внешних зависимостей (только Python 3).

Запуск локально:
  python3 app.py

На сервере (VPS / Railway / Render):
  PORT=8080 python3 app.py
"""

from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
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
SITE_ROOT = ROOT  # index.html находится рядом с app.py
DB_PATH = Path(os.environ.get("FREEZ_DB", str(ROOT / "freez.db")))
UPLOAD_DIR = Path(os.environ.get("FREEZ_UPLOAD_DIR", str(ROOT / "uploads")))
MAX_LAUNCHER_SIZE = 100 * 1024 * 1024
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
ADMIN_NICK = os.environ.get("FREEZ_ADMIN_NICK", "migi").lower()

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
        CREATE TABLE IF NOT EXISTS launcher (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            filename TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at REAL NOT NULL,
            uploaded_by TEXT NOT NULL
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
    # совместимо с фронтом (SHA-256 hex), плюс соль на сервере
    salt = "freez_v1"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def user_public(row: sqlite3.Row) -> dict:
    return {
        "uid": row["uid"],
        "nick": row["nick"],
        "email": row["email"],
        "role": row["role"],
        "subscription": bool(row["subscription"]),
        "subscriptionUntil": row["subscription_until"],
        "blocked": bool(row["blocked"]),
    }


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, x-user-uid, x-admin-uid, x-session-token")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return {}


def get_user_by_token(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    row = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.uid = s.uid WHERE s.token = ?",
        (token,),
    ).fetchone()
    return row


def create_session(conn: sqlite3.Connection, uid: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions(token, uid, created_at) VALUES (?, ?, ?)",
        (token, uid, time.time()),
    )
    conn.commit()
    return token


def is_admin_user(row: sqlite3.Row | None) -> bool:
    if not row:
        return False
    return row["role"] == "admin" or str(row["nick"]).lower() == ADMIN_NICK


class Handler(BaseHTTPRequestHandler):
    server_version = "FreezServer/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-user-uid, x-admin-uid, x-session-token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._serve_file(SITE_ROOT / "index.html", "text/html; charset=utf-8")
        if path == "/downloads/launcher":
            conn = db()
            try:
                row = conn.execute("SELECT * FROM launcher WHERE id = 1").fetchone()
            finally:
                conn.close()
            if not row:
                return json_response(self, 404, {"message": "Лаунчер ещё не загружен"})
            fp = Path(row["path"])
            if not fp.is_file():
                return json_response(self, 404, {"message": "Файл лаунчера не найден"})
            return self._serve_file(fp, "application/octet-stream", download_name=row["filename"])
        # static next to index
        safe = path.lstrip("/").replace("..", "")
        file_path = SITE_ROOT / safe
        if file_path.is_file():
            ctype = "application/octet-stream"
            if safe.endswith(".png"):
                ctype = "image/png"
            elif safe.endswith(".jpg") or safe.endswith(".jpeg"):
                ctype = "image/jpeg"
            elif safe.endswith(".css"):
                ctype = "text/css"
            elif safe.endswith(".js"):
                ctype = "application/javascript"
            return self._serve_file(file_path, ctype)
        if path == "/api/health":
            return json_response(self, 200, {"ok": True, "db": str(DB_PATH)})
        json_response(self, 404, {"message": "Not found"})

    def _serve_file(self, file_path: Path, content_type: str, download_name: str | None = None) -> None:
        if not file_path.is_file():
            return json_response(self, 404, {"message": "Not found"})
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        if download_name:
            safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', download_name)
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return json_response(self, 404, {"message": "Not found"})
        route = path[len("/api") :]  # /auth/register ...
        if route == "/admin/launcher":
            return self._admin_launcher_upload()
        body = read_json(self)
        conn = db()
        try:
            self._route(conn, route, body)
        finally:
            conn.close()

    def _route(self, conn: sqlite3.Connection, route: str, body: dict) -> None:
        token = self.headers.get("x-session-token") or body.get("token")
        me = get_user_by_token(conn, token)

        if route == "/auth/register":
            return self._register(conn, body)
        if route == "/auth/login":
            return self._login(conn, body)
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
        if route == "/keys/redeem":
            return self._redeem(conn, me, body)
        if route == "/auth/me":
            if not me:
                return json_response(self, 401, {"message": "Не авторизован"})
            return json_response(self, 200, {"user": user_public(me), "token": token})
        json_response(self, 404, {"message": "Unknown endpoint"})

    def _register(self, conn: sqlite3.Connection, body: dict) -> None:
        nick = str(body.get("nick") or "").strip()
        email = str(body.get("email") or "").strip().lower()
        password = str(body.get("password") or "")
        if len(nick) < 3:
            return json_response(self, 400, {"message": "Никнейм должен быть минимум 3 символа."})
        if not EMAIL_RE.match(email):
            return json_response(self, 400, {"message": "Введите корректную почту."})
        if len(password) < 8:
            return json_response(self, 400, {"message": "Пароль должен быть минимум 8 символов."})
        if conn.execute("SELECT 1 FROM users WHERE nick = ? COLLATE NOCASE", (nick,)).fetchone():
            return json_response(self, 400, {"message": "Такой никнейм уже зарегистрирован."})
        if conn.execute("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone():
            return json_response(self, 400, {"message": "Эта почта уже используется."})
        role = "admin" if nick.lower() == ADMIN_NICK else "user"
        cur = conn.execute(
            """INSERT INTO users(nick, email, password_hash, role, subscription, subscription_until, blocked, created_at)
               VALUES (?, ?, ?, ?, 0, NULL, 0, ?)""",
            (nick, email, hash_password(password), role, time.time()),
        )
        uid = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        token = create_session(conn, uid)
        data = user_public(row)
        data["token"] = token
        json_response(self, 200, data)

    def _login(self, conn: sqlite3.Connection, body: dict) -> None:
        nick = str(body.get("nick") or "").strip()
        password = str(body.get("password") or "")
        row = conn.execute("SELECT * FROM users WHERE nick = ? COLLATE NOCASE", (nick,)).fetchone()
        if not row:
            return json_response(self, 400, {"message": "Аккаунт не найден. Создайте аккаунт."})
        if row["blocked"]:
            return json_response(self, 403, {"message": "Аккаунт заблокирован."})
        if row["password_hash"] != hash_password(password):
            return json_response(self, 400, {"message": "Неверный пароль."})
        token = create_session(conn, row["uid"])
        data = user_public(row)
        data["token"] = token
        json_response(self, 200, data)

    def _change_password(self, conn: sqlite3.Connection, me: sqlite3.Row | None, body: dict) -> None:
        if not me:
            return json_response(self, 401, {"message": "Не авторизован"})
        current = str(body.get("currentPassword") or "")
        new = str(body.get("newPassword") or "")
        if len(new) < 8:
            return json_response(self, 400, {"message": "Новый пароль должен быть минимум 8 символов."})
        if me["password_hash"] != hash_password(current):
            return json_response(self, 400, {"message": "Неверный текущий пароль."})
        conn.execute("UPDATE users SET password_hash = ? WHERE uid = ?", (hash_password(new), me["uid"]))
        conn.commit()
        json_response(self, 200, {"ok": True})

    def _change_email(self, conn: sqlite3.Connection, me: sqlite3.Row | None, body: dict) -> None:
        if not me:
            return json_response(self, 401, {"message": "Не авторизован"})
        email = str(body.get("email") or "").strip().lower()
        password = str(body.get("password") or "")
        if not EMAIL_RE.match(email):
            return json_response(self, 400, {"message": "Введите корректную почту."})
        if me["password_hash"] != hash_password(password):
            return json_response(self, 400, {"message": "Неверный пароль."})
        taken = conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND uid != ?",
            (email, me["uid"]),
        ).fetchone()
        if taken:
            return json_response(self, 400, {"message": "Эта почта уже используется."})
        conn.execute("UPDATE users SET email = ? WHERE uid = ?", (email, me["uid"]))
        conn.commit()
        json_response(self, 200, {"ok": True, "email": email})

    def _admin_launcher_upload(self) -> None:
        token = self.headers.get("x-session-token")
        conn = db()
        try:
            me = get_user_by_token(conn, token)
            if not is_admin_user(me):
                return json_response(self, 403, {"message": "Нет доступа"})
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_LAUNCHER_SIZE:
                return json_response(self, 413, {"message": "Файл слишком большой. Максимум 100 МБ."})
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                return json_response(self, 400, {"message": "Ожидается файл."})
            raw = self.rfile.read(length)
            msg = BytesParser(policy=policy.default).parsebytes(
                (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode() + raw
            )
            part = next((p for p in msg.walk() if p.get_content_disposition() == "form-data" and p.get_filename()), None)
            if not part:
                return json_response(self, 400, {"message": "Файл не найден в форме."})
            filename = Path(part.get_filename()).name
            if not filename or filename in {".", ".."}:
                return json_response(self, 400, {"message": "Некорректное имя файла."})
            allowed = {".exe", ".zip", ".jar", ".msi", ".7z"}
            if Path(filename).suffix.lower() not in allowed:
                return json_response(self, 400, {"message": "Разрешены только .exe, .zip, .jar, .msi и .7z."})
            data = part.get_payload(decode=True) or b""
            if not data:
                return json_response(self, 400, {"message": "Файл пустой."})
            if len(data) > MAX_LAUNCHER_SIZE:
                return json_response(self, 413, {"message": "Файл слишком большой. Максимум 100 МБ."})
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            target = UPLOAD_DIR / "launcher" + Path(filename).suffix.lower() if False else UPLOAD_DIR / ("launcher" + Path(filename).suffix.lower())
            target.write_bytes(data)
            conn.execute("DELETE FROM launcher WHERE id = 1")
            conn.execute("INSERT INTO launcher(id, filename, path, size, uploaded_at, uploaded_by) VALUES (1,?,?,?,?,?)", (filename, str(target), len(data), time.time(), me["nick"]))
            conn.commit()
            return json_response(self, 200, {"ok": True, "filename": filename, "size": len(data), "url": "/downloads/launcher"})
        except Exception as exc:
            return json_response(self, 500, {"message": "Не удалось загрузить лаунчер", "detail": str(exc)})
        finally:
            conn.close()

    def _admin_users(self, conn: sqlite3.Connection, me: sqlite3.Row | None) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})
        rows = conn.execute("SELECT * FROM users ORDER BY uid ASC").fetchall()
        json_response(self, 200, {"users": [user_public(r) for r in rows]})

    def _admin_key(self, conn: sqlite3.Connection, me: sqlite3.Row | None, body: dict) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})
        key = str(body.get("key") or "").strip().upper()
        duration = str(body.get("duration") or "7")
        target = str(body.get("target") or "").strip()
        if not key:
            return json_response(self, 400, {"message": "Ключ не задан"})
        try:
            conn.execute(
                """INSERT INTO keys(key, duration, target, active, created_by, created_at)
                   VALUES (?, ?, ?, 1, ?, ?)""",
                (key, duration, target, me["nick"], time.time()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return json_response(self, 400, {"message": "Такой ключ уже есть"})
        json_response(self, 200, {"ok": True, "key": key})

    def _admin_reset_password(self, conn: sqlite3.Connection, me: sqlite3.Row | None, body: dict) -> None:
        if not is_admin_user(me):
            return json_response(self, 403, {"message": "Нет доступа"})
        uid = int(body.get("uid") or 0)
        user = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        if not user:
            return json_response(self, 404, {"message": "Пользователь не найден"})
        temp = secrets.token_urlsafe(8)
        conn.execute("UPDATE users SET password_hash = ? WHERE uid = ?", (hash_password(temp), uid))
        conn.execute("DELETE FROM sessions WHERE uid = ?", (uid,))
        conn.commit()
        json_response(self, 200, {"ok": True, "tempPassword": temp})

    def _redeem(self, conn: sqlite3.Connection, me: sqlite3.Row | None, body: dict) -> None:
        if not me:
            return json_response(self, 401, {"message": "Сначала войдите в аккаунт."})
        raw = str(body.get("key") or "").strip().upper()
        if not raw:
            return json_response(self, 400, {"message": "Введите ключ."})
        item = conn.execute("SELECT * FROM keys WHERE key = ? AND active = 1", (raw,)).fetchone()
        if not item:
            return json_response(self, 400, {"message": "Ключ не найден или уже использован."})
        target = str(item["target"] or "").strip().lower()
        if target and target not in (str(me["nick"]).lower(), str(me["uid"])):
            return json_response(self, 400, {"message": "Этот ключ предназначен для другого пользователя."})
        duration = item["duration"]
        expires = None
        if duration != "forever":
            try:
                days = int(duration)
                expires = int((time.time() + days * 86400) * 1000)
            except ValueError:
                expires = None
        conn.execute(
            "UPDATE users SET subscription = 1, subscription_until = ? WHERE uid = ?",
            (expires, me["uid"]),
        )
        conn.execute(
            "UPDATE keys SET active = 0, used_by = ?, used_at = ? WHERE id = ?",
            (me["nick"], time.time(), item["id"]),
        )
        conn.commit()
        json_response(
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
    if not (SITE_ROOT / "index.html").is_file():
        print("WARNING: index.html not found at", SITE_ROOT / "index.html")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Freez server: http://%s:%s" % (HOST, PORT))
    print("SQLite DB:   ", DB_PATH)
    print("Admin nick:  ", ADMIN_NICK)
    print("API base:    /api")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
