import streamlit as st
import sqlite3
import threading
from contextlib import contextmanager
import os
import hashlib
import hmac
import base64
import re

# Optional: auto-refresh so other users' changes show quickly
try:
    from streamlit_autorefresh import st_autorefresh
    AUTO_REFRESH_AVAILABLE = True
except ImportError:
    AUTO_REFRESH_AVAILABLE = False

# ---------- CONFIG ----------
DB_PATH = "storage.db"
db_lock = threading.Lock()  # reduce race conditions on writes

# ---------- SECURITY HELPERS ----------
def sanitize_username(username: str) -> str:
    """
    Keep only safe characters for username and limit length.
    """
    username = (username or "").strip()
    # allow letters, digits, underscore, dot, dash
    username = re.sub(r"[^a-zA-Z0-9_.-]", "", username)
    return username[:32]


def hash_password(password: str) -> str:
    """
    Strong password hashing using PBKDF2-HMAC-SHA256 with salt.
    Result format: base64(salt)$base64(hash)
    """
    password = (password or "").strip()
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verify password against stored hash.
    """
    try:
        password = (password or "").strip()
        salt_b64, hash_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------- DB HELPERS ----------
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        # Items table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        # Users table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
            """
        )

        # Access tokens for account creation
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            )
            """
        )

        # Logs table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now')),
                username TEXT,
                action TEXT NOT NULL,
                details TEXT
            )
            """
        )

        # If logs table already existed without timestamp column, add it
        cur = conn.execute("PRAGMA table_info(logs)")
        cols = [row["name"] for row in cur.fetchall()]
        if "timestamp" not in cols:
            conn.execute(
                "ALTER TABLE logs ADD COLUMN timestamp TEXT DEFAULT (datetime('now'))"
            )

        # Seed a default access token if it doesn't already exist
        # (INSERT OR IGNORE avoids duplicate error)
        conn.execute(
            "INSERT OR IGNORE INTO access_tokens (token, used) VALUES (?, 0)",
            ("MYTOKEN123",),
        )
        DEFAULT_TOKENS = ["TOKEN1", "TOKEN2", "VIP123", "ADMIN888"]

        for t in DEFAULT_TOKENS:
            cur = conn.execute("SELECT token FROM access_tokens WHERE token = ?", (t,))
            if cur.fetchone() is None:
                conn.execute("INSERT INTO access_tokens (token, used) VALUES (?, 0)", (t,))



def fetch_items():
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT id, name, quantity FROM items ORDER BY id ASC"
        )
        return cur.fetchall()


def add_item(name: str, quantity: int, username: str | None):
    with db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO items (name, quantity) VALUES (?, ?)",
            (name, quantity),
        )
        log_action(conn, username, "add_item", f"name={name}, qty={quantity}")


def adjust_quantity(item_id: int, delta: int, username: str | None):
    with db_lock, get_conn() as conn:
        conn.execute(
            "UPDATE items SET quantity = quantity + ? WHERE id = ?",
            (delta, item_id),
        )
        log_action(conn, username, "update_item", f"id={item_id}, delta={delta}")


def delete_item(item_id: int, username: str | None):
    with db_lock, get_conn() as conn:
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        log_action(conn, username, "delete_item", f"id={item_id}")


def log_action(conn, username: str | None, action: str, details: str | None):
    conn.execute(
        "INSERT INTO logs (username, action, details) VALUES (?, ?, ?)",
        (username, action, details),
    )


def fetch_logs(limit: int = 50):
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT id, timestamp, username, action, details
            FROM logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()


# ---------- AUTH DB HELPERS ----------
def create_user(username: str, password: str, access_token: str) -> tuple[bool, str]:
    username = sanitize_username(username)
    password = (password or "").strip()
    access_token = (access_token or "").strip()

    if not username:
        return False, "用戶名稱不可空白。"
    if len(password) < 8:
        return False, "密碼至少需要 8 個字元。"
    if not access_token:
        return False, "請輸入 Access Token。"

    with db_lock, get_conn() as conn:
        # Check token
        cur = conn.execute(
            "SELECT id, used FROM access_tokens WHERE token = ?",
            (access_token,),
        )
        row = cur.fetchone()
        if row is None:
            return False, "Access Token 無效。"
        if row["used"]:
            return False, "Access Token 已被使用。"

        # Create user
        pwd_hash = hash_password(password)
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pwd_hash),
            )
        except sqlite3.IntegrityError:
            return False, "此用戶名稱已存在。"

        # Mark token as used
        conn.execute(
            "UPDATE access_tokens SET used = 1 WHERE id = ?",
            (row["id"],),
        )

        # Log
        log_action(conn, username, "create_account", "Account created via access token.")

    return True, "帳號建立成功！"


def authenticate_user(username: str, password: str) -> bool:
    username = sanitize_username(username)
    password = (password or "").strip()

    with get_conn() as conn:
        cur = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        return verify_password(password, row["password_hash"])


# ---------- AUTH SESSION STATE ----------
def init_auth_state():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "username" not in st.session_state:
        st.session_state.username = None


# ---------- LOGIN / SIGNUP PAGE ----------
def login_page():
    st.title("🔐 庫存系統登入")

    tab_login, tab_signup = st.tabs(["登入", "建立帳號"])

    # ---- Login tab ----
    with tab_login:
        with st.form("login_form"):
            raw_username = st.text_input("用戶名稱")
            username = sanitize_username(raw_username)
            password = st.text_input("密碼", type="password")
            submitted = st.form_submit_button("登入")

        if submitted:
            if not username or not password.strip():
                st.error("請輸入用戶名稱與密碼。")
            else:
                if authenticate_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    # Log login
                    with get_conn() as conn:
                        log_action(conn, username, "login", "User logged in.")
                    st.success("登入成功，跳轉中...")
                    st.rerun()
                else:
                    st.error("帳號或密碼錯誤。")

    # ---- Signup tab ----
    with tab_signup:
        st.write("需要有效的 Access Token 才能建立帳號。")
        with st.form("signup_form"):
            raw_new_user = st.text_input("新用戶名稱")
            new_user = sanitize_username(raw_new_user)
            new_pwd = st.text_input("新密碼", type="password")
            new_pwd2 = st.text_input("確認密碼", type="password")
            token = st.text_input("Access Token")
            signup_submitted = st.form_submit_button("建立帳號")

        if signup_submitted:
            if new_pwd != new_pwd2:
                st.error("兩次輸入的密碼不一致。")
            else:
                ok, msg = create_user(new_user, new_pwd, token)
                if ok:
                    # Auto login after successful account creation
                    st.session_state.authenticated = True
                    st.session_state.username = sanitize_username(new_user)
                    st.success(msg + " 已自動登入，跳轉中...")
                    st.rerun()
                else:
                    st.error(msg)


# ---------- MAIN PAGE ----------
def main_page():
    # Optional auto-refresh to sync items between users
    if AUTO_REFRESH_AVAILABLE:
        st_autorefresh(interval=3000, key="inventory_refresh")  # 3s

    st.title("📦 庫存管理")

    # Sidebar: user info + logout
    with st.sidebar:
        st.markdown(f"**目前登入:** {st.session_state.username}")
        if st.button("登出"):
            with get_conn() as conn:
                log_action(conn, st.session_state.username, "logout", "User logged out.")
            st.session_state.authenticated = False
            st.session_state.username = None
            st.rerun()

    # Ensure DB exists
    init_db()

    # ---- Add new item section ----
    st.subheader("新增物品到庫存")

    with st.form(key="add_item_form"):
        new_name = st.text_input("物品名稱")
        new_qty = st.number_input(
            "物品數量 (克 / 盒)",
            step=1,
            value=0,
            format="%d",
        )
        add_btn = st.form_submit_button("新增物品")

        if add_btn:
            if not new_name.strip():
                st.warning("請輸入物品名稱")
            else:
                add_item(new_name.strip(), int(new_qty), st.session_state.username)
                st.success(f"新增了 {int(new_qty)} (克 / 盒) '{new_name}' ")
                st.rerun()

    st.markdown("---")

    # ---- Storage table section ----
    st.subheader("現有庫存")

    items = fetch_items()

    if not items:
        st.info("沒有任何庫存紀錄。請新增一些項目。")
    else:
        # Read-only table view
        st.table(
            [
                {
                    "物品名字": row["name"],
                    "數量 (克/盒)": row["quantity"],
                }
                for row in items
            ]
        )

        st.markdown("### 更新物品數量 / 刪除物品")

        for row in items:
            col2, col3, col4 = st.columns([3, 3, 4])

            with col2:
                st.write(row["name"])

            with col3:
                st.write(f"庫存: **{row['quantity']}**")

            with col4:
                form_key = f"update_form_{row['id']}"
                with st.form(key=form_key):
                    delta = st.number_input(
                        "Change (+ / -)",
                        value=0,
                        step=1,
                        format="%d",
                        key=f"delta_{row['id']}",
                    )
                    update_btn = st.form_submit_button("確認更新")
                    delete_btn = st.form_submit_button("刪除物品")

                    if update_btn:
                        if delta == 0:
                            st.warning("請輸入非零的變更數量。")
                        else:
                            adjust_quantity(row["id"], int(delta), st.session_state.username)
                            st.success(
                                f"已更新物品 {row['name']} 變更 {int(delta)}。"
                            )
                            st.rerun()

                    elif delete_btn:
                        delete_item(row["id"], st.session_state.username)
                        st.success(f"已移除物品 {row['name']}。")
                        st.rerun()

    # ---- Logs section ----
    st.markdown("---")
    st.subheader("操作紀錄 (最近 50 筆)")

    logs = fetch_logs(limit=50)
    if not logs:
        st.info("目前沒有操作紀錄。")
    else:
        st.table(
            [
                {
                    "時間": row["timestamp"],
                    "用戶": row["username"],
                    "動作": row["action"],
                    "細節": row["details"],
                }
                for row in logs
            ]
        )


# ---------- APP ENTRY ----------
st.set_page_config(
    page_title="Storage Manager",
    layout="centered",   # disable wide mode by default; dark mode via config.toml
)

# Initialise auth + DB once at startup
init_auth_state()
init_db()

if not st.session_state.authenticated:
    login_page()
else:
    main_page()
