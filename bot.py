import os
import sys
import re
import time
import socket
import string
import random
import threading
import traceback
import base64
import urllib.parse
import io
import json
import warnings
import urllib3
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
from waitress import serve
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from functools import wraps
from collections import defaultdict
import uuid

import telebot
from telebot import types
import psycopg2
from psycopg2 import pool
import requests
from bs4 import BeautifulSoup
from flask import Flask, request
from dotenv import load_dotenv

load_dotenv()

# ==================== КОНСТАНТЫ ====================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

_cache_lock = Lock()
_subscribe_monitor_lock = Lock()
_captcha_lock = Lock()
_keys_lock = Lock()
_user_name_cache_lock = Lock()
_last_activity_lock = Lock()
_autopost_lock = Lock()
_rate_limit_lock = Lock()

# ==================== ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ ====================

BOT_TOKEN = os.getenv('BOT_TOKEN')
OWNER_IDS = [8176196456, 1910232650]
DATABASE_URL = os.getenv('DATABASE_URL')

# Обязательные каналы для подписки
REQUIRED_CHANNELS = [
    {'id': -1003668283208, 'link': 'https://t.me/ciorsa', 'name': 'ciorsa'},
 
]

# Поддержка
SUPPORT_USERS = ['@severny_3d', '@mel1ste']

# ==================== ИНИЦИАЛИЗАЦИЯ ====================

bot = telebot.TeleBot(BOT_TOKEN, threaded=True, num_threads=8)
app = Flask(__name__)

db_pool = None

def init_db_pool():
    global db_pool
    try:
        db_pool = pool.SimpleConnectionPool(1, 20, DATABASE_URL)
        print("[db_pool] ✅ Пул соединений инициализирован (min=1, max=20)")
    except Exception as e:
        print(f"[db_pool] ❌ Ошибка инициализации пула: {e}")
        db_pool = None

def get_db_connection():
    if db_pool:
        return db_pool.getconn()
    return psycopg2.connect(DATABASE_URL)

def return_db_connection(conn):
    if db_pool and conn:
        db_pool.putconn(conn)
    elif conn:
        conn.close()

# ==================== КЭШ ====================

_user_name_cache = {}
USER_NAME_CACHE_TTL = 3600

_bot_username = None
_bot_username_lock = Lock()

def get_user_display_name_cached(user_id):
    current_time = int(time.time())
    
    with _user_name_cache_lock:
        cached = _user_name_cache.get(user_id, {})
        if cached.get('timestamp', 0) > current_time - USER_NAME_CACHE_TTL:
            return cached.get('name', str(user_id))
    
    try:
        chat = bot.get_chat(user_id)
        if chat.username:
            name = f"@{chat.username}"
        else:
            name = chat.first_name or ''
            if chat.last_name:
                name += ' ' + chat.last_name
            name = name.strip() or str(user_id)
    except:
        name = str(user_id)
    
    with _user_name_cache_lock:
        _user_name_cache[user_id] = {
            'name': name,
            'timestamp': current_time
        }
    
    return name

def get_user_display_name(user_id):
    return get_user_display_name_cached(user_id)

def get_bot_username():
    global _bot_username
    with _bot_username_lock:
        if not _bot_username:
            try:
                _bot_username = bot.get_me().username
            except Exception as e:
                print(f"[get_bot_username] Ошибка: {e}")
                return "WSVPN_Bobot"
        return _bot_username

def clear_user_cache(user_id):
    with _user_name_cache_lock:
        if user_id in _user_name_cache:
            del _user_name_cache[user_id]

# ==================== ФУНКЦИИ ПРОВЕРКИ ПРАВ ====================

def is_owner(user_id):
    return user_id in OWNER_IDS

def is_admin(user_id):
    if user_id in OWNER_IDS:
        return True
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM admins WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()
        return_db_connection(conn)
        return result is not None
    except:
        return False

def get_admin_role_name(user_id):
    if user_id in OWNER_IDS:
        return "👑 Владелец"
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT role FROM admins WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        if result:
            role = result[0]
            if role == 'owner': return "👑 Владелец"
            elif role == 'senior': return "⭐ Старший админ"
            elif role == 'junior': return "🔹 Младший админ"
            elif role == 'support': return "🟢 Поддержка"
        return "❌ Не админ"
    finally:
        cur.close()
        return_db_connection(conn)

def get_admin_permissions(user_id):
    if user_id in OWNER_IDS:
        return {p: True for p in [
            'check_user', 'user_info', 'add_days', 'remove_days', 
            'block_user', 'unblock_user', 'announce', 'manage_keys',
            'manage_users', 'admin_stats', 'admin_panel', 'view_logs',
            'manage_admins', 'autopost'
        ]}
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT permissions FROM admins WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        if result and result[0]:
            try:
                return json.loads(result[0])
            except:
                pass
    finally:
        cur.close()
        return_db_connection(conn)
    return {}

def has_permission(user_id, permission):
    if user_id in OWNER_IDS:
        return True
    perms = get_admin_permissions(user_id)
    return perms.get(permission, False)

PERMISSIONS = {
    'check_user': 'Проверка пользователя (/check)',
    'user_info': 'Информация о пользователе (/user)',
    'add_days': 'Выдача дней (/add_days)',
    'remove_days': 'Забирание дней (/remove_days)',
    'block_user': 'Блокировка (/block)',
    'unblock_user': 'Разблокировка (/unblock)',
    'announce': 'Рассылка',
    'manage_keys': 'Управление ключами',
    'autopost': 'Автопостинг',
    'manage_admins': 'Управление админами',
    'manage_users': 'Управление пользователями',
    'admin_stats': 'Статистика бота',
    'admin_panel': 'Доступ к админ-панели',
    'view_logs': 'Просмотр логов',
}

ROLE_PRESETS = {
    'owner': {
        'name': '👑 Владелец',
        'permissions': {p: True for p in PERMISSIONS}
    },
    'senior': {
        'name': '⭐ Старший админ',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': True, 'remove_days': True,
            'block_user': True, 'unblock_user': True, 'announce': True, 'manage_keys': True,
            'autopost': True, 'manage_admins': False, 'manage_users': True, 'admin_stats': True,
            'admin_panel': True, 'view_logs': True,
        }
    },
    'junior': {
        'name': '🔹 Младший админ',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': True, 'remove_days': True,
            'block_user': True, 'unblock_user': True, 'announce': False, 'manage_keys': False,
            'autopost': False, 'manage_admins': False, 'manage_users': False, 'admin_stats': False,
            'admin_panel': True, 'view_logs': False,
        }
    },
    'support': {
        'name': '🟢 Поддержка',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': False, 'remove_days': False,
            'block_user': False, 'unblock_user': False, 'announce': False, 'manage_keys': False,
            'autopost': False, 'manage_admins': False, 'manage_users': False, 'admin_stats': False,
            'admin_panel': False, 'view_logs': False,
        }
    }
}

def update_admin_permissions(user_id, permissions_dict):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE admins SET permissions = %s WHERE user_id = %s", (json.dumps(permissions_dict), user_id))
        conn.commit()
    finally:
        cur.close()
        return_db_connection(conn)

def log_admin_action(admin_id, action, target_id=None, details=None, target_name=None, ip_address=None):
    try:
        admin_name = get_user_display_name(admin_id)
        if target_id:
            target_name = target_name or get_user_display_name(target_id)
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO admin_logs 
                (admin_id, admin_name, action, target_id, target_name, details, ip_address, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                admin_id,
                admin_name,
                action,
                target_id,
                target_name,
                details,
                ip_address,
                int(time.time())
            ))
            conn.commit()
        finally:
            cur.close()
            return_db_connection(conn)
    except Exception as e:
        print(f"[log_admin_action] Ошибка: {e}")

# ==================== БАЗА ДАННЫХ ====================

KEY_TEMPLATE = """\
#profile-title: WSVPN🐈‍⬛
#profile-update-interval: 1
#support-url: https://t.me/severny_3d
#channel: 📢 https://t.me/WS_JuJuB01_vpn_keys
#subscription-userinfo: upload=0; download=0; total=10995116277760000; expire={expire}
{keys}"""

DEFAULT_KEYS = [
    'vless://00000000-0000-0000-0000-000000000001@1.1.1.1:443?type=tcp&security=tls#Demo-Key',
]

_keys_cache = None
_keys_cache_time = 0
KEYS_CACHE_TTL = 60

def get_setting(key, default='0'):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
        result = cur.fetchone()
        return result[0] if result else default
    finally:
        cur.close()
        return_db_connection(conn)

def set_setting(key, value):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = %s",
            (key, value, value)
        )
        conn.commit()
    finally:
        cur.close()
        return_db_connection(conn)

def increment_setting(key, by=1):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE
            SET value = (COALESCE(settings.value, '0')::bigint + %s)::text
            RETURNING value
        """, (key, str(by), by))
        new_value = cur.fetchone()[0]
        conn.commit()
        return int(new_value)
    finally:
        cur.close()
        return_db_connection(conn)

def get_keys_from_db():
    global _keys_cache, _keys_cache_time
    current_time = time.time()
    
    with _keys_lock:
        if _keys_cache is not None and current_time - _keys_cache_time < KEYS_CACHE_TTL:
            return _keys_cache.copy()
        
        val = get_setting('vless_keys', '')
        keys = [k for k in val.split('|||') if k] if val else []
        
        _keys_cache = keys.copy()
        _keys_cache_time = current_time
        return keys

def save_keys_to_db(keys):
    global _keys_cache, _keys_cache_time
    cleaned = list(dict.fromkeys(k for k in keys if k))
    
    with _keys_lock:
        set_setting('vless_keys', '|||'.join(cleaned))
        _keys_cache = cleaned.copy()
        _keys_cache_time = time.time()

def get_subscription_keys_from_db():
    val = get_setting('subscription_keys', '')
    if not val:
        return []
    return [k for k in val.split('|||') if k]

def save_subscription_keys_to_db(keys):
    cleaned = list(dict.fromkeys(k for k in keys if k))
    set_setting('subscription_keys', '|||'.join(cleaned))

def generate_subscription_token():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=12))

def ensure_bot_start_time():
    existing = get_setting('bot_start_time', '')
    if not existing:
        set_setting('bot_start_time', str(int(time.time())))

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                subscription_end BIGINT,
                notified_3days INTEGER DEFAULT 0,
                last_activity BIGINT DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                token TEXT UNIQUE,
                username TEXT,
                telegram_id BIGINT,
                notified_expired INTEGER DEFAULT 0,
                is_frozen INTEGER DEFAULT 0,
                frozen_days_left INTEGER DEFAULT 0,
                frozen_at BIGINT DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_subscription_end ON users(subscription_end)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_notified_3days ON users(notified_3days)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id)")
        conn.commit()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                user_id BIGINT PRIMARY KEY
            )
        """)
        conn.commit()
        
        cur.execute("ALTER TABLE admins ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'junior'")
        cur.execute("ALTER TABLE admins ADD COLUMN IF NOT EXISTS permissions TEXT")
        cur.execute("ALTER TABLE admins ADD COLUMN IF NOT EXISTS added_by BIGINT")
        cur.execute("ALTER TABLE admins ADD COLUMN IF NOT EXISTS added_at BIGINT")
        conn.commit()
        
        for admin_id in OWNER_IDS:
            try:
                cur.execute("""
                    INSERT INTO admins (user_id, role, permissions, added_by, added_at) 
                    VALUES (%s, 'owner', %s, %s, %s) 
                    ON CONFLICT (user_id) DO UPDATE SET role = 'owner', permissions = %s
                """, (admin_id, json.dumps({p: True for p in PERMISSIONS}), admin_id, int(time.time()), json.dumps({p: True for p in PERMISSIONS})))
            except Exception as e:
                print(f"[init] Ошибка добавления админа {admin_id}: {e}")
        conn.commit()
        print(f"[init] ✅ Владельцы добавлены: {OWNER_IDS}")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id SERIAL PRIMARY KEY,
                referrer_id BIGINT,
                referred_id BIGINT,
                reward_date BIGINT,
                rewarded INTEGER DEFAULT 0,
                referrer_subscribed INTEGER DEFAULT 0,
                referred_subscribed INTEGER DEFAULT 0,
                UNIQUE(referrer_id, referred_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY,
                admin_id BIGINT NOT NULL,
                admin_name TEXT,
                action TEXT NOT NULL,
                target_id BIGINT,
                target_name TEXT,
                details TEXT,
                ip_address TEXT,
                created_at BIGINT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_admin_id ON admin_logs(admin_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at DESC)")
        
        conn.commit()
    except Exception as e:
        print(f"[init_db] Критическая ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
        raise
    finally:
        cur.close()
        return_db_connection(conn)

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def get_bot_base_url():
    base_url = os.getenv('PUBLIC_URL', '')
    if not base_url:
        base_url = os.getenv('RENDER_EXTERNAL_URL', 'https://potyjnovpn.apruxdomain.store')
    base_url = base_url.rstrip('/')
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    return base_url

def is_subscribed(user_id):
    for channel in REQUIRED_CHANNELS:
        try:
            member = bot.get_chat_member(channel['id'], user_id)
            if member.status not in ['member', 'administrator', 'creator']:
                return False
        except:
            return False
    return True

def get_unsubscribed_channels(user_id):
    unsubscribed = []
    for channel in REQUIRED_CHANNELS:
        try:
            member = bot.get_chat_member(channel['id'], user_id)
            if member.status not in ['member', 'administrator', 'creator']:
                unsubscribed.append(channel)
        except:
            unsubscribed.append(channel)
    return unsubscribed

def is_blocked(user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT is_blocked FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()
        return_db_connection(conn)
        return result[0] == 1 if result else False
    except:
        return False

def get_subscription_link(user_id):
    if is_blocked(user_id):
        return None
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT token, is_frozen FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        if not result:
            return None
        
        token, is_frozen = result
        
        if is_frozen:
            return None
        
        if token:
            base_url = get_bot_base_url()
            return f"{base_url}/sub/{token}"
        
        token = generate_subscription_token()
        cur.execute("""
            UPDATE users SET token = %s 
            WHERE user_id = %s AND token IS NULL
            RETURNING token
        """, (token, user_id))
        result = cur.fetchone()
        if not result:
            cur.execute("SELECT token FROM users WHERE user_id = %s", (user_id,))
            result = cur.fetchone()
            token = result[0] if result else token
        conn.commit()
        base_url = get_bot_base_url()
        return f"{base_url}/sub/{token}"
    except Exception as e:
        print(f"[get_subscription_link] Ошибка: {e}")
        return None
    finally:
        cur.close()
        return_db_connection(conn)

def get_user_id_from_input(user_input):
    user_input = user_input.strip()
    
    tg_match = re.search(r'tg://user\?id=(\d+)', user_input)
    if tg_match:
        try:
            user_id = int(tg_match.group(1))
            if user_id <= 0:
                return None
            return user_id
        except:
            return None
    
    tme_match = re.search(r't\.me/([a-zA-Z0-9_]+)', user_input)
    if tme_match:
        username = tme_match.group(1)
        try:
            chat = bot.get_chat(f"@{username}")
            return chat.id
        except:
            return None
    
    if user_input.startswith('@'):
        try:
            chat = bot.get_chat(user_input)
            return chat.id
        except:
            return None
    
    try:
        user_id = int(user_input)
        if user_id <= 0:
            return None
        return user_id
    except:
        return None

def get_bot_stats():
    ensure_bot_start_time()
    start_time = int(get_setting('bot_start_time', str(int(time.time()))))
    uptime_seconds = int(time.time()) - start_time
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]
    finally:
        cur.close()
        return_db_connection(conn)
    
    return {
        'uptime_text': _format_duration(uptime_seconds),
        'total_users': total_users,
        'current_keys': len(get_keys_from_db()),
    }

def _format_duration(seconds):
    seconds = max(0, int(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f"{days} дн")
    if hours or days:
        parts.append(f"{hours} ч")
    parts.append(f"{minutes} мин")
    return ' '.join(parts)

# ==================== КЛАВИАТУРЫ ====================

def main_menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    kb.row(
        types.KeyboardButton("👤 Личный кабинет"),
        types.KeyboardButton("📡 Моя подписка")
    )
    kb.row(
        types.KeyboardButton("👥 Рефералы"),
        types.KeyboardButton("🏆 Топ рефералов")
    )
    kb.row(
        types.KeyboardButton("ℹ️ Стаж бота"),
        types.KeyboardButton("📋 Правила")
    )
    kb.row(
        types.KeyboardButton("❓ Поддержка")
    )
    return kb

def subscribe_button():
    kb = types.InlineKeyboardMarkup(row_width=1)
    for channel in REQUIRED_CHANNELS:
        kb.add(types.InlineKeyboardButton(
            f"📢 Подписаться на {channel['name']}", 
            url=channel['link']
        ))
    kb.add(types.InlineKeyboardButton(
        "✅ Проверить подписку", 
        callback_data="check_sub"
    ))
    return kb

def get_subscription_required_text():
    channels_text = "\n".join([f"• {ch['name']}: {ch['link']}" for ch in REQUIRED_CHANNELS])
    return (
        f"⚠️ *Для использования бота необходимо подписаться на каналы:*\n\n"
        f"{channels_text}\n\n"
        f"После подписки нажмите кнопку проверки."
    )

def blocked_message():
    return f"🚫 Вы заблокированы. Обратитесь: @severny_3d или @mel1ste"

def admin_menu():
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📢 Рассылка", callback_data="admin_announce"),
        types.InlineKeyboardButton("👥 Управление пользователями", callback_data="admin_manage_users")
    )
    kb.add(
        types.InlineKeyboardButton("🔑 Управление ключами", callback_data="admin_keys"),
        types.InlineKeyboardButton("📡 Автопостинг", callback_data="admin_autopost")
    )
    kb.add(
        types.InlineKeyboardButton("👑 Управление админами", callback_data="admin_manage_admins"),
        types.InlineKeyboardButton("📋 Логи админов", callback_data="admin_view_logs")
    )
    kb.add(
        types.InlineKeyboardButton("🏠 Главное меню", callback_data="admin_back")
    )
    return kb

def build_user_list_keyboard(users, page, filter_type='all'):
    kb = types.InlineKeyboardMarkup(row_width=2)
    per_page = 5
    start = page * per_page
    end = start + per_page
    current_time = int(time.time())

    page_users = users[start:end]
    user_data = {}
    if page_users:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            placeholders = ','.join(['%s'] * len(page_users))
            query = """
                SELECT user_id, COALESCE(subscription_end, 0), COALESCE(is_blocked, 0) 
                FROM users WHERE user_id IN ({})
            """.format(placeholders)
            cur.execute(query, tuple(page_users))
            user_data = {row[0]: row for row in cur.fetchall()}
        finally:
            cur.close()
            return_db_connection(conn)

    for uid in page_users:
        row = user_data.get(uid)
        if row:
            _, sub_end, blk = row
            if blk == 1:
                icon = "🚫"
            elif sub_end > 0 and sub_end > current_time:
                icon = "🟢"
            else:
                icon = "🔴"
        else:
            icon = "❓"
        admin_icon = "👑 " if is_admin(uid) else ""
        name = get_user_display_name(uid)
        display = f"{icon} {admin_icon}{name}"[:40]
        kb.add(types.InlineKeyboardButton(display, callback_data=f"user_{uid}"))

    nav_row = []
    if page > 0:
        nav_row.append(types.InlineKeyboardButton("◀️ Назад", callback_data=f"page_{page-1}_{filter_type}"))
    if end < len(users):
        nav_row.append(types.InlineKeyboardButton("Вперед ▶️", callback_data=f"page_{page+1}_{filter_type}"))
    if nav_row:
        kb.row(*nav_row)

    kb.row(
        types.InlineKeyboardButton("🟢 Активные", callback_data="filter_active"),
        types.InlineKeyboardButton("🔴 Неактивные", callback_data="filter_inactive")
    )
    kb.row(
        types.InlineKeyboardButton("👑 Админы", callback_data="filter_admins"),
        types.InlineKeyboardButton("📋 Все", callback_data="filter_all")
    )
    kb.row(
        types.InlineKeyboardButton("🔙 Назад в админ-панель", callback_data="admin_back_panel"),
        types.InlineKeyboardButton("❌ Закрыть", callback_data="close_manage")
    )
    return kb

# ==================== КЭШИ И ДАННЫЕ ====================

search_cache = {}
announce_data = {}
manage_cache = {}
captcha_sessions = {}
keys_loading = {}

CAPTCHA_TIMEOUT = 300
SUBSCRIBE_MONITOR = {'timestamps': [], 'blocked_until': 0}
SUBSCRIBE_LIMIT = 100
SUBSCRIBE_BAN_TIME = 3600

def check_subscribe_rate():
    with _subscribe_monitor_lock:
        current_time = int(time.time())
        SUBSCRIBE_MONITOR['timestamps'] = [t for t in SUBSCRIBE_MONITOR['timestamps'] if current_time - t < 60]
        count = len(SUBSCRIBE_MONITOR['timestamps'])
        if current_time < SUBSCRIBE_MONITOR['blocked_until']:
            remaining = SUBSCRIBE_MONITOR['blocked_until'] - current_time
            return False, f"⏳ Подписки заблокированы. Осталось {remaining//60} мин."
        if count > SUBSCRIBE_LIMIT:
            SUBSCRIBE_MONITOR['blocked_until'] = current_time + SUBSCRIBE_BAN_TIME
            return False, "⚠️ Слишком много подписок. Попробуйте через час."
        return True, "OK"

def add_subscribe_record(user_id):
    with _subscribe_monitor_lock:
        SUBSCRIBE_MONITOR['timestamps'].append(int(time.time()))

def process_referral(referrer_id, referred_id):
    if referrer_id == referred_id:
        return False, "Нельзя пригласить самого себя"
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s FOR UPDATE", (referrer_id,))
        referrer_exists = cur.fetchone()
        if not referrer_exists:
            return False, "Реферер не найден"
        
        cur.execute("SELECT user_id, is_blocked FROM users WHERE user_id = %s FOR UPDATE", (referred_id,))
        referred = cur.fetchone()
        if not referred:
            return False, "Реферал не зарегистрирован в боте"
        if referred[1] == 1:
            return False, "Реферал заблокирован"
        
        referrer_subscribed = is_subscribed(referrer_id)
        referred_subscribed = is_subscribed(referred_id)
        
        if not referred_subscribed:
            return False, "Реферал не подписан на каналы"
        
        today_start = int(time.time()) - 24 * 60 * 60
        cur.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = %s AND reward_date > %s",
            (referrer_id, today_start)
        )
        count = cur.fetchone()[0]
        if count >= 10:
            return False, "Лимит рефералов (10 в день) превышен"
        
        current_time = int(time.time())
        try:
            cur.execute("""
                INSERT INTO referrals (referrer_id, referred_id, reward_date, rewarded, referrer_subscribed, referred_subscribed) 
                VALUES (%s, %s, %s, 0, %s, %s)
            """, (referrer_id, referred_id, current_time, 1 if referrer_subscribed else 0, 1))
            conn.commit()
        except Exception as e:
            conn.rollback()
            if 'unique' in str(e).lower():
                return False, "Этот пользователь уже был приглашен"
            raise
        
        if referrer_subscribed:
            cur.execute("SELECT subscription_end FROM users WHERE user_id = %s FOR UPDATE", (referrer_id,))
            ref_result = cur.fetchone()
            if ref_result:
                new_end = ref_result[0] + 3 * 24 * 60 * 60
                cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0 WHERE user_id = %s", 
                           (new_end, referrer_id))
                cur.execute(
                    "UPDATE referrals SET rewarded = 1 WHERE referrer_id = %s AND referred_id = %s",
                    (referrer_id, referred_id)
                )
                conn.commit()
                try:
                    bot.send_message(referrer_id, "🎉 Вам начислено +3 дня за нового реферала!")
                except:
                    pass
                return True, "Реферал добавлен, начислено +3 дня"
        
        conn.commit()
        return True, "Реферал сохранен"
    except Exception as e:
        print(f"[process_referral] Ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
        return False, f"Ошибка: {e}"
    finally:
        try:
            if cur:
                cur.close()
        except:
            pass
        if conn:
            return_db_connection(conn)

# ==================== ОСНОВНЫЕ ОБРАБОТЧИКИ ====================

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.chat.type != 'private':
        bot.reply_to(message, "⚠️ Бот работает только в ЛС.")
        return

    user_id = message.from_user.id
    current_time = int(time.time())

    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return

    # Проверяем подписку на каналы
    unsubscribed = get_unsubscribed_channels(user_id)
    
    if unsubscribed:
        bot.send_message(
            user_id,
            get_subscription_required_text(),
            reply_markup=subscribe_button(),
            parse_mode="Markdown"
        )
        return

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        existing_user = cur.fetchone()
    finally:
        cur.close()
        return_db_connection(conn)

    if existing_user:
        if not is_subscribed(user_id):
            bot.reply_to(message, "⚠️ Подпишитесь на каналы.", reply_markup=subscribe_button())
            return
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("UPDATE users SET last_activity = %s WHERE user_id = %s", (current_time, user_id))
            conn.commit()
        finally:
            cur.close()
            return_db_connection(conn)
        bot.send_message(user_id, "👋 Добро пожаловать!", reply_markup=main_menu())
        return

    # Новая регистрация
    referrer_id = None
    if message.text:
        parts = message.text.strip().split()
        if len(parts) > 1:
            for part in parts:
                if part.startswith('ref_'):
                    try:
                        ref = int(part[4:])
                        if ref != user_id:
                            referrer_id = ref
                        break
                    except ValueError:
                        continue

    _register_user(user_id, referrer_id)

@bot.callback_query_handler(func=lambda call: call.data == "check_sub")
def callback_check_sub(call):
    user_id = call.from_user.id
    
    if is_blocked(user_id):
        bot.answer_callback_query(call.id, "🚫 Вы заблокированы.")
        return
    
    unsubscribed = get_unsubscribed_channels(user_id)
    
    if not unsubscribed:
        bot.answer_callback_query(call.id, "✅ Подписка подтверждена!")
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
            user_exists = cur.fetchone()
        finally:
            cur.close()
            return_db_connection(conn)
        
        if not user_exists:
            _register_user(user_id, None)
        else:
            bot.send_message(user_id, "👋 Добро пожаловать!", reply_markup=main_menu())
    else:
        channels_text = "\n".join([f"• {ch['name']}: {ch['link']}" for ch in unsubscribed])
        bot.answer_callback_query(
            call.id, 
            f"❌ Подпишитесь на каналы:\n{channels_text}",
            show_alert=True
        )

def _register_user(user_id, referrer_id=None):
    current_time = int(time.time())
    registered = False
    conn = None
    cur = None
    
    for attempt in range(5):
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users WHERE user_id = %s FOR UPDATE", (user_id,))
            existing = cur.fetchone()
            
            if existing:
                registered = True
                break
            
            token = generate_subscription_token()
            sub_end = current_time + 7 * 24 * 60 * 60
            
            username = None
            try:
                chat = bot.get_chat(user_id)
                username = chat.username
            except:
                pass
            
            cur.execute("""
                INSERT INTO users (user_id, subscription_end, last_activity, is_blocked, token, username, telegram_id) 
                VALUES (%s, %s, %s, 0, %s, %s, %s)
            """, (user_id, sub_end, current_time, token, username, user_id))
            conn.commit()
            registered = True
            break
        except Exception as e:
            conn.rollback()
            if 'unique' in str(e).lower() and 'token' in str(e).lower():
                print(f"[_register_user] Конфликт токена, попытка {attempt+1}")
                continue
            print(f"[_register_user] Ошибка: {e}")
            break
        finally:
            try:
                if cur:
                    cur.close()
            except:
                pass
            if conn:
                return_db_connection(conn)
    
    if not registered:
        print(f"[_register_user] Не удалось зарегистрировать {user_id}")
        return
    
    if referrer_id:
        success, msg = process_referral(referrer_id, user_id)
        if success:
            try:
                bot.send_message(referrer_id, f"🔔 Новый реферал! Пользователь {get_user_display_name(user_id)} зарегистрировался по вашей ссылке.")
            except:
                pass
    
    try:
        bot.send_message(user_id, "🎉 Добро пожаловать! Вам выдана подписка на 7 дней.")
        bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
    except Exception as e:
        print(f"[_register_user] Ошибка отправки приветствия: {e}")

# ==================== МЕНЮ ====================

@bot.message_handler(func=lambda m: m.text == "👤 Личный кабинет")
def cabinet(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    current_time = int(time.time())
    
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), COALESCE(is_frozen, 0), COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Используйте /start")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        
        if is_frozen:
            status = "❄️ Заморожена"
            time_left = f"{frozen_days_left} дн"
            expire_date = "Заморожена"
        elif subscription_end > 0 and subscription_end > current_time:
            days_left = (subscription_end - current_time) // (24 * 60 * 60)
            status = "✅ Активна"
            time_left = f"{days_left} дн"
            expire_date = datetime.fromtimestamp(subscription_end).strftime("%d.%m.%Y в %H:%M")
        else:
            status = "❌ Не активна"
            time_left = "Закончилась"
            expire_date = "Закончилась"
        
        text = (
            f"👤 *Личный кабинет*\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"📊 Статус: {status}\n"
            f"📅 Подписка до: `{expire_date}`\n"
            f"⏳ Осталось: `{time_left}`"
        )
        
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("🔄 Обновить", callback_data="refresh_cabinet"))
        
        bot.reply_to(message, text, parse_mode="Markdown", reply_markup=kb)
    finally:
        cur.close()
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "refresh_cabinet")
def callback_refresh_cabinet(call):
    user_id = call.from_user.id
    clear_user_cache(user_id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), COALESCE(is_frozen, 0), COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        current_time = int(time.time())
        
        if is_frozen:
            status = "❄️ Заморожена"
            time_left = f"{frozen_days_left} дн"
            expire_date = "Заморожена"
        elif subscription_end > 0 and subscription_end > current_time:
            days_left = (subscription_end - current_time) // (24 * 60 * 60)
            status = "✅ Активна"
            time_left = f"{days_left} дн"
            expire_date = datetime.fromtimestamp(subscription_end).strftime("%d.%m.%Y в %H:%M")
        else:
            status = "❌ Не активна"
            time_left = "Закончилась"
            expire_date = "Закончилась"
        
        text = (
            f"👤 *Личный кабинет*\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"📊 Статус: {status}\n"
            f"📅 Подписка до: `{expire_date}`\n"
            f"⏳ Осталось: `{time_left}`"
        )
        
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("🔄 Обновить", callback_data="refresh_cabinet"))
        
        try:
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id,
                                 parse_mode="Markdown", reply_markup=kb)
        except:
            bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)
        
        bot.answer_callback_query(call.id, "✅ Обновлено!")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "📡 Моя подписка")
def my_subscription(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    current_time = int(time.time())
    
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    if not is_subscribed(user_id):
        bot.reply_to(message, "⚠️ Подпишитесь на каналы.", reply_markup=subscribe_button())
        return
    
    clear_user_cache(user_id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), COALESCE(is_frozen, 0), COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ /start")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        
        if is_frozen:
            text = (
                f"📡 *Моя подписка*\n\n"
                f"❄️ Заморожена\n"
                f"⏳ Сохранено: `{frozen_days_left}` дн.\n\n"
                f"Нажмите кнопку ниже чтобы разморозить.\n\n"
                f"💬 Поддержка: @severny_3d или @mel1ste"
            )
            kb = types.InlineKeyboardMarkup()
            kb.add(types.InlineKeyboardButton("🔥 Разморозить", callback_data="unfreeze_sub"))
            bot.reply_to(message, text, parse_mode="Markdown", reply_markup=kb)
            return
        
        link = get_subscription_link(user_id) if subscription_end > 0 and subscription_end > current_time else None
        days_left = (subscription_end - current_time) // (24 * 60 * 60) if subscription_end > 0 and subscription_end > current_time else 0

        if subscription_end > 0 and subscription_end > current_time:
            status_text = f"✅ Активна\n⏳ Осталось: `{days_left}` дн."
        else:
            status_text = "❌ Не активна\n\nДля продления обратитесь к администратору:"

        text = (
            f"📡 *Моя подписка*\n\n"
            f"📊 Статус: {status_text}\n\n"
        )
        
        if link:
            text += (
                f"┌ 🔗 *Ссылка для импорта:*\n"
                f"│ `{link}`\n"
                f"│\n"
                f"├ 🔄 *Для белых списков (Яндекс):*\n"
                f"│ `https://translate.yandex.ru/translate?url={link}`\n"
                f"│\n"
                f"└ ℹ️ *Ссылка автообновляется*\n\n"
            )
        
        text += f"💬 Поддержка: @severny_3d или @mel1ste"

        kb = types.InlineKeyboardMarkup(row_width=2)
        
        if link:
            kb.add(
                types.InlineKeyboardButton("📋 Обычная", callback_data=f"copy_link_{user_id}"),
                types.InlineKeyboardButton("🔄 Белые списки", callback_data=f"copy_yandex_{user_id}")
            )
            kb.row(
                types.InlineKeyboardButton("🍎 Incy iOS", url="https://apps.apple.com/ru/app/incy/id6756943388"),
                types.InlineKeyboardButton("🤖 Incy Android", url="https://play.google.com/store/apps/details?id=llc.itdev.incy")
            )
            if days_left > 0:
                kb.add(types.InlineKeyboardButton(
                    f"❄️ Заморозить ({days_left} дн.)",
                    callback_data="freeze_sub"
                ))
        else:
            kb.add(types.InlineKeyboardButton(
                "💬 Связаться с поддержкой",
                url="https://t.me/severny_3d"
            ))
            kb.add(types.InlineKeyboardButton(
                "🔄 Обновить статус",
                callback_data="refresh_cabinet"
            ))
        
        bot.reply_to(message, text, parse_mode="Markdown", reply_markup=kb)
    finally:
        cur.close()
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "freeze_sub")
def callback_freeze_sub(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT subscription_end FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            return
        
        current_time = int(time.time())
        sub_end = result[0]
        days_left = max(0, (sub_end - current_time) // (24 * 60 * 60))
        
    finally:
        cur.close()
        return_db_connection(conn)
    
    text = (
        f"❄️ *Заморозка подписки*\n\n"
        f"⚠️ *Внимание!*\n\n"
        f"• Текущий токен подписки будет *удалён*\n"
        f"• Сохранится: `{days_left}` дней\n"
        f"• При разморозке генерируется *новый токен*\n"
        f"• Старая ссылка перестанет работать\n\n"
        f"Вы уверены?"
    )
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("✅ Да, заморозить", callback_data="freeze_confirm"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="freeze_cancel")
    )
    
    try:
        bot.edit_message_text(
            text, call.message.chat.id, call.message.message_id,
            parse_mode="Markdown", reply_markup=kb
        )
    except:
        bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

@bot.callback_query_handler(func=lambda call: call.data == "freeze_confirm")
def callback_freeze_confirm(call):
    user_id = call.from_user.id
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT subscription_end FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        current_time = int(time.time())
        sub_end = result[0]
        days_left = max(0, (sub_end - current_time) // (24 * 60 * 60))
        
        cur.execute("""
            UPDATE users SET 
                is_frozen = 1,
                frozen_days_left = %s,
                frozen_at = %s,
                token = NULL,
                subscription_end = 0
            WHERE user_id = %s
        """, (days_left, int(time.time()), user_id))
        conn.commit()
        clear_user_cache(user_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    bot.answer_callback_query(call.id, "❄️ Подписка заморожена!")
    
    try:
        bot.edit_message_text(
            f"❄️ *Подписка заморожена*\n\n⏳ Сохранено: `{days_left}` дней\n\nДля разморозки нажмите кнопку в разделе 📡 *Моя подписка*",
            call.message.chat.id, call.message.message_id,
            parse_mode="Markdown"
        )
    except:
        pass

@bot.callback_query_handler(func=lambda call: call.data == "freeze_cancel")
def callback_freeze_cancel(call):
    bot.answer_callback_query(call.id, "❌ Отменено")
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except:
        pass

@bot.callback_query_handler(func=lambda call: call.data == "unfreeze_sub")
def callback_unfreeze_sub(call):
    user_id = call.from_user.id
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT frozen_days_left FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        frozen_days = result[0] or 0
        current_time = int(time.time())
        new_sub_end = current_time + frozen_days * 24 * 60 * 60
        new_token = generate_subscription_token()
        
        cur.execute("""
            UPDATE users SET
                is_frozen = 0,
                frozen_days_left = 0,
                frozen_at = 0,
                subscription_end = %s,
                token = %s,
                notified_3days = 0
            WHERE user_id = %s
        """, (new_sub_end, new_token, user_id))
        conn.commit()
        clear_user_cache(user_id)
        
        new_link = f"{get_bot_base_url()}/sub/{new_token}"
    finally:
        cur.close()
        return_db_connection(conn)
    
    bot.answer_callback_query(call.id, "🔥 Подписка разморожена!")
    
    text = (
        f"🔥 *Подписка разморожена!*\n\n"
        f"✅ Активна ещё: `{frozen_days}` дней\n"
        f"🔗 Новая ссылка:\n"
        f"`{new_link}`\n\n"
        f"⚠️ Старая ссылка больше не работает!\n"
        f"Обновите подписку в клиенте."
    )
    
    try:
        bot.edit_message_text(
            text, call.message.chat.id, call.message.message_id,
            parse_mode="Markdown"
        )
    except:
        bot.send_message(user_id, text, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith('copy_link_'))
def callback_copy_link(call):
    user_id = call.from_user.id
    target_id = int(call.data.split('_')[2])

    if user_id != target_id:
        bot.answer_callback_query(call.id, "❌ Это не ваша ссылка.")
        return

    link = get_subscription_link(user_id)
    if not link:
        bot.answer_callback_query(call.id, "❌ Подписка заморожена или недоступна.")
        return

    bot.send_message(
        user_id,
        f"📋 *Обычная ссылка:*\n\n`{link}`\n\nНажмите на сообщение и скопируйте текст.",
        parse_mode="Markdown"
    )
    bot.answer_callback_query(call.id, "✅ Ссылка отправлена!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('copy_yandex_'))
def callback_copy_yandex(call):
    user_id = call.from_user.id
    target_id = int(call.data.split('_')[2])

    if user_id != target_id:
        bot.answer_callback_query(call.id, "❌ Это не ваша ссылка.")
        return

    link = get_subscription_link(user_id)
    if not link:
        bot.answer_callback_query(call.id, "❌ Подписка заморожена или недоступна.")
        return
    
    yandex_link = f"https://translate.yandex.ru/translate?url={link}"

    bot.send_message(
        user_id,
        f"🔄 *Ссылка для белых списков:*\n\n`{yandex_link}`\n\nНажмите на сообщение и скопируйте текст.\n\nℹ️ Ссылка автообновляется при белых списках.",
        parse_mode="Markdown"
    )
    bot.answer_callback_query(call.id, "✅ Ссылка для белых списков отправлена!")

@bot.message_handler(func=lambda m: m.text == "👥 Рефералы")
def referrals(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cur.fetchone():
            bot.reply_to(message, "❌ Вы не зарегистрированы. Используйте /start")
            return
        cur.execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = %s", (user_id,))
        total = cur.fetchone()[0]
        today_start = int(time.time()) - 24 * 60 * 60
        cur.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = %s AND reward_date > %s",
            (user_id, today_start)
        )
        today = cur.fetchone()[0]
        bot_username = get_bot_username()
        ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
        text = f"👥 *Рефералы*\n\n📊 Всего: {total}\n📅 Сегодня: {today} / 10\n\n🔗 Ссылка: `{ref_link}`\n\n📌 За каждого друга +3 дня."
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "🏆 Топ рефералов")
def top_referrals(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT referrer_id, COUNT(*) FROM referrals GROUP BY referrer_id ORDER BY COUNT(*) DESC LIMIT 10")
        rows = cur.fetchall()
        if not rows:
            bot.reply_to(message, "📭 Нет рефералов.")
            return
        text = "🏆 *Топ рефералов:*\n\n"
        medals = ['🥇', '🥈', '🥉']
        for i, (ref_id, count) in enumerate(rows):
            name = get_user_display_name(ref_id)
            icon = medals[i] if i < 3 else f"{i+1}."
            text += f"{icon} {name} — {count} реф.\n"
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "ℹ️ Стаж бота")
def bot_stats_command(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    stats = get_bot_stats()
    text = (
        f"📊 *Статистика*\n\n"
        f"⏳ Стаж: {stats['uptime_text']}\n"
        f"👥 Пользователей: {stats['total_users']}\n"
        f"📦 Ключей: {stats['current_keys']}"
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(func=lambda m: m.text == "📋 Правила")
def rules(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    text = (
        "⚠️ *Правила:*\n\n"
        "🛑 *Запрещено:*\n"
        "• Торрент и P2P\n"
        "• Банковские операции\n\n"
        f"💬 Поддержка: @severny_3d или @mel1ste"
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(func=lambda m: m.text == "❓ Поддержка")
def support(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("🆘 @severny_3d", url="https://t.me/severny_3d"),
        types.InlineKeyboardButton("🆘 @mel1ste", url="https://t.me/mel1ste")
    )
    
    text = (
        "💬 *Поддержка:*\n\n"
        "📌 Свяжитесь с нами:\n"
        "• @severny_3d\n"
        "• @mel1ste\n\n"
        "Нажмите на кнопку ниже для быстрого перехода."
    )
    bot.reply_to(message, text, parse_mode="Markdown", reply_markup=kb)

# ==================== АДМИН-ПАНЕЛЬ ====================

@bot.message_handler(commands=['admin'])
def admin_panel(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if not is_admin(user_id):
        bot.reply_to(message, "⛔️ Нет доступа.")
        return
    if not has_permission(user_id, 'admin_panel'):
        bot.reply_to(message, "⛔️ У вас нет доступа к админ-панели.")
        return
    role_name = get_admin_role_name(user_id)
    bot.send_message(user_id, f"🏛️ Админ панель\n\n👤 Ваша роль: {role_name}", reply_markup=admin_menu())

# ==================== АДМИН-КОЛБЭКИ ====================

@bot.callback_query_handler(func=lambda call: (
    call.data.startswith('admin_') or 
    call.data.startswith('add_admin_') or
    call.data.startswith('edit_admin_') or
    call.data.startswith('toggle_perm_') or
    call.data.startswith('reset_perm_') or
    call.data.startswith('autopost_') or
    call.data.startswith('announce_') or
    call.data.startswith('broadcast_') or
    call.data == 'edit_admin_perms' or
    call.data == 'admin_back_panel' or
    call.data == 'admin_back'
))
def admin_callback(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    data = call.data

    # ===== НАВИГАЦИЯ =====
    if data == "admin_back":
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        bot.send_message(user_id, "🏠 Главное меню", reply_markup=main_menu())
        bot.answer_callback_query(call.id)
        return

    if data == "admin_back_panel":
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        role_name = get_admin_role_name(user_id)
        bot.send_message(
            user_id,
            f"🏛️ Админ панель\n\n👤 Ваша роль: {role_name}",
            reply_markup=admin_menu()
        )
        bot.answer_callback_query(call.id)
        return

    # ===== УПРАВЛЕНИЕ КЛЮЧАМИ =====
    if data in ("admin_keys", "admin_sub_keys_load", "admin_sub_keys_finish") or data.startswith("admin_keys_") or data.startswith("admin_auto_update_"):
        if not has_permission(user_id, 'manage_keys'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        
        if data == "admin_keys":
            show_keys_menu(user_id, call.message.chat.id, call.message.message_id)
        elif data == "admin_keys_load":
            callback_admin_keys_load(call)
        elif data == "admin_keys_load_finish":
            callback_admin_keys_load_finish(call)
        elif data == "admin_keys_load_cancel":
            callback_admin_keys_load_cancel(call)
        elif data == "admin_keys_clean_dead":
            callback_admin_keys_clean_dead(call)
        elif data == "admin_keys_clear_all":
            callback_admin_keys_clear_all(call)
        elif data == "admin_keys_clear_confirm":
            callback_admin_keys_clear_confirm(call)
        elif data == "admin_keys_back":
            callback_admin_keys_back(call)
        return

    # ===== РАССЫЛКА =====
    if data == "admin_announce":
        if not has_permission(user_id, 'announce'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("📨 В ЛС", callback_data="announce_dm"),
            types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
        )
        try:
            bot.edit_message_text(
                "📢 *Рассылка*\n\nВыберите куда:",
                call.message.chat.id, call.message.message_id,
                parse_mode="Markdown", reply_markup=kb
            )
        except:
            bot.send_message(user_id, "📢 *Рассылка*\n\nВыберите куда:",
                           parse_mode="Markdown", reply_markup=kb)
        return

    if data == "announce_dm":
        if not has_permission(user_id, 'announce'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id, "📝 Отправьте текст/медиа")
        bot.send_message(user_id, "📨 *Рассылка в ЛС*\n\nОтправьте текст или медиа.", parse_mode="Markdown")
        with _cache_lock:
            announce_data[user_id] = {'type': 'dm', 'waiting': True, 'timestamp': int(time.time())}
        return

    # ===== УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ =====
    if data == "admin_manage_users":
        if not has_permission(user_id, 'manage_users'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users ORDER BY user_id")
            users = [row[0] for row in cur.fetchall()]
        finally:
            cur.close()
            return_db_connection(conn)
        if not users:
            try:
                bot.edit_message_text("📭 Нет пользователей.",
                                     call.message.chat.id, call.message.message_id)
            except:
                bot.send_message(user_id, "📭 Нет пользователей.")
            return
        with _cache_lock:
            manage_cache[user_id] = {
                'users': users, 
                'filter': 'all',
                'timestamp': int(time.time())
            }
        kb = build_user_list_keyboard(users, 0, 'all')
        try:
            bot.edit_message_text(
                f"👥 Пользователи ({len(users)}):",
                call.message.chat.id, call.message.message_id,
                reply_markup=kb
            )
        except:
            bot.send_message(user_id, f"👥 Пользователи ({len(users)}):", reply_markup=kb)
        return

    # ===== УПРАВЛЕНИЕ АДМИНАМИ =====
    if data == "admin_manage_admins":
        if not has_permission(user_id, 'manage_admins'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав на управление админами.")
            return
        bot.answer_callback_query(call.id)
        _show_admin_list(call)
        return

    if data == "edit_admin_perms":
        if not has_permission(user_id, 'manage_admins'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id, role FROM admins")
            admins = cur.fetchall()
        finally:
            cur.close()
            return_db_connection(conn)
        # Фильтруем владельцев
        admins = [(a_id, role) for a_id, role in admins if a_id not in OWNER_IDS]
        if not admins:
            bot.send_message(user_id, "❌ Нет других админов для настройки.")
            return
        kb = types.InlineKeyboardMarkup(row_width=1)
        for admin_id_item, role in admins:
            name = get_user_display_name(admin_id_item)
            kb.add(types.InlineKeyboardButton(
                f"{name} ({role})",
                callback_data=f"edit_admin_{admin_id_item}"
            ))
        kb.add(types.InlineKeyboardButton("🔙 Назад", callback_data="admin_manage_admins"))
        try:
            bot.edit_message_text(
                "⚙️ *Выберите админа для настройки прав:*",
                call.message.chat.id, call.message.message_id,
                parse_mode="Markdown", reply_markup=kb
            )
        except:
            bot.send_message(user_id, "⚙️ *Выберите админа для настройки прав:*",
                           parse_mode="Markdown", reply_markup=kb)
        return

    if data.startswith("add_admin_role_"):
        if not has_permission(user_id, 'manage_admins'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        with _cache_lock:
            if user_id in search_cache:
                del search_cache[user_id]
        role = data.split('_')[3]
        with _cache_lock:
            search_cache[user_id] = {
                'action': 'add_admin',
                'role': role,
                'timestamp': int(time.time())
            }
        bot.answer_callback_query(call.id, f"✅ Выбрана роль: {ROLE_PRESETS[role]['name']}")
        bot.send_message(
            user_id,
            f"👑 Выбрана роль: {ROLE_PRESETS[role]['name']}\n\n"
            "Отправьте ID или @username пользователя.",
            parse_mode="Markdown"
        )
        return

    if data == "add_admin_start":
        if not has_permission(user_id, 'manage_admins'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.add(
            types.InlineKeyboardButton("⭐ Старший админ", callback_data="add_admin_role_senior"),
            types.InlineKeyboardButton("🔹 Младший админ", callback_data="add_admin_role_junior"),
            types.InlineKeyboardButton("🟢 Поддержка", callback_data="add_admin_role_support")
        )
        kb.add(types.InlineKeyboardButton("🔙 Назад", callback_data="admin_manage_admins"))
        bot.send_message(
            user_id,
            "👑 *Добавление админа*\n\n"
            "Выберите роль для нового админа, затем отправьте ID или @username пользователя.",
            parse_mode="Markdown",
            reply_markup=kb
        )
        return

    # ===== ЛОГИ =====
    if data == "admin_view_logs":
        if not has_permission(user_id, 'view_logs'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав на просмотр логов")
            return
        bot.answer_callback_query(call.id)
        _show_admin_logs(call)
        return

    # ===== АВТОПОСТИНГ =====
    if data == "admin_autopost":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id)
        show_autopost_menu(call, user_id)
        return

    if data == "autopost_back":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        show_autopost_menu(call, user_id)
        return

    if data == "autopost_load_keys":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id, "📥 Отправьте ключи")
        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.add(
            types.InlineKeyboardButton("✅ Завершить", callback_data="autopost_load_finish"),
            types.InlineKeyboardButton("🔙 Назад", callback_data="autopost_back")
        )
        msg = bot.send_message(user_id, "📥 Отправляйте ключи.\nКогда закончите - нажмите Завершить.", reply_markup=kb)
        with _cache_lock:
            autopost_loading[user_id] = {'keys': [], 'message_id': msg.message_id, 'timestamp': int(time.time())}
        return

    if data == "autopost_load_finish":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        with _cache_lock:
            if user_id not in autopost_loading:
                bot.answer_callback_query(call.id, "❌ Нет загрузки")
                return
            keys = autopost_loading[user_id]['keys']
            del autopost_loading[user_id]
        if not keys:
            bot.answer_callback_query(call.id, "❌ Нет ключей")
            return
        save_keys_to_db(keys)
        bot.answer_callback_query(call.id, f"✅ Сохранено {len(keys)}")
        show_autopost_menu(call, user_id)
        return

    if data == "autopost_start":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        keys = get_keys_from_db()
        if not keys:
            bot.answer_callback_query(call.id, "❌ Нет ключей")
            return
        config = get_autopost_config()
        config['enabled'] = True
        save_autopost_config(config)
        log_admin_action(user_id, "Запустил автопостинг")
        bot.answer_callback_query(call.id, "🚀 Запущен!")
        set_setting('autopost_last_post', '0')
        show_autopost_menu(call, user_id)
        return

    if data == "autopost_stop":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        config = get_autopost_config()
        config['enabled'] = False
        save_autopost_config(config)
        log_admin_action(user_id, "Остановил автопостинг")
        bot.answer_callback_query(call.id, "⏹ Автопостинг остановлен!")
        show_autopost_menu(call, user_id)
        return

    if data == "autopost_channel_settings":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        config = get_autopost_config()
        text = f"⚙️ *Канал*\n\n📢 Текущий: {config['channel_id']}"
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("📢 Сменить", callback_data="autopost_change_channel"),
            types.InlineKeyboardButton("🔙 Назад", callback_data="autopost_back")
        )
        try:
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=kb)
        except:
            bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)
        return

    if data == "autopost_change_channel":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id, "🔄 Отправьте новый канал")
        bot.send_message(user_id, "📢 Отправьте ссылку или ID канала.\nПример: `-1001234567890` или `@channel`", parse_mode="Markdown")
        with _cache_lock:
            search_cache[user_id] = {'action': 'autopost_set_channel', 'timestamp': int(time.time())}
        return

    if data == "autopost_interval_settings":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        config = get_autopost_config()
        text = f"⏱ *Интервал*\n\n⏱ Текущий: {config['interval'] // 60} мин"
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("⏱ Изменить", callback_data="autopost_set_interval"),
            types.InlineKeyboardButton("🔙 Назад", callback_data="autopost_back")
        )
        try:
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=kb)
        except:
            bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)
        return

    if data == "autopost_set_interval":
        if not has_permission(user_id, 'autopost'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        bot.answer_callback_query(call.id, "⏱ Введите минуты")
        bot.send_message(user_id, "⏱ Введите интервал в минутах (5-1440):", parse_mode="Markdown")
        with _cache_lock:
            search_cache[user_id] = {'action': 'autopost_set_interval', 'timestamp': int(time.time())}
        return

    # ===== ОБРАБОТКА edit_admin_{id} =====
    if data.startswith("edit_admin_") and data != 'edit_admin_perms':
        if not has_permission(user_id, 'manage_admins'):
            bot.answer_callback_query(call.id, "⛔️ Нет прав")
            return
        try:
            target_id = int(data.split('_')[2])
        except (ValueError, IndexError):
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        if target_id in OWNER_IDS:
            bot.answer_callback_query(call.id, "❌ Нельзя редактировать владельца.")
            return
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT role FROM admins WHERE user_id = %s", (target_id,))
            result = cur.fetchone()
        finally:
            cur.close()
            return_db_connection(conn)
        if not result:
            bot.answer_callback_query(call.id, "❌ Админ не найден.")
            return
        _redraw_admin_perms(call, target_id)
        bot.answer_callback_query(call.id)
        return

    # ===== ДЕЛЕГИРОВАНИЕ ОСТАЛЬНЫХ CALLBACK =====
    if data.startswith("filter_") or data.startswith("page_") or data in ('back_to_list', 'close_manage'):
        callback_user_list_nav(call)
        return

    if data.startswith("user_") and len(data.split('_')) == 2:
        callback_user_detail(call)
        return

    if data.startswith(('grant_admin_', 'remove_admin_')):
        if data.startswith('grant_admin_'):
            callback_grant_admin(call)
        else:
            callback_remove_admin(call)
        return

    if data.startswith(('give_sub_', 'prolong_', 'remove_days_', 'remove_sub_', 'block_', 'unblock_')):
        if data.startswith('give_sub_'):
            callback_give_sub(call)
        elif data.startswith('prolong_'):
            callback_prolong(call)
        elif data.startswith('remove_days_'):
            callback_remove_days(call)
        elif data.startswith('remove_sub_'):
            callback_remove_sub(call)
        elif data.startswith('block_'):
            callback_block(call)
        elif data.startswith('unblock_'):
            callback_unblock(call)
        return

    if data.startswith(('copy_link_', 'copy_yandex_')):
        if data.startswith('copy_link_'):
            callback_copy_link(call)
        else:
            callback_copy_yandex(call)
        return

    bot.answer_callback_query(call.id)

# ==================== АДМИН-ФУНКЦИИ ====================

def _show_admin_list(call):
    user_id = call.from_user.id
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id, role FROM admins ORDER BY user_id")
        admins = cur.fetchall()
    finally:
        cur.close()
        return_db_connection(conn)

    text = "👑 *Управление админами*\n\n"
    for admin_id, role in admins:
        name = get_user_display_name(admin_id)
        role_name = ROLE_PRESETS.get(role, {}).get('name', role)
        is_owner_text = "👑 " if admin_id in OWNER_IDS else ""
        text += f"• {is_owner_text}{role_name} {name} (`{admin_id}`)\n"
    text += f"\n👑 Владельцы: {', '.join([get_user_display_name(uid) for uid in OWNER_IDS])}"

    kb = types.InlineKeyboardMarkup(row_width=2)
    if has_permission(user_id, 'manage_admins'):
        kb.add(
            types.InlineKeyboardButton("➕ Добавить админа", callback_data="add_admin_start"),
            types.InlineKeyboardButton("⚙️ Настроить права", callback_data="edit_admin_perms")
        )
    kb.add(types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel"))

    try:
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except:
        bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

def _redraw_admin_perms(call, target_id):
    user_id = call.from_user.id
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT role FROM admins WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
    finally:
        cur.close()
        return_db_connection(conn)
    
    if not result:
        return
    
    current_perms = get_admin_permissions(target_id)
    role = result[0] or 'junior'
    role_name = ROLE_PRESETS.get(role, {}).get('name', role)
    name = get_user_display_name(target_id)
    
    text = (
        f"⚙️ *Настройка прав*\n\n"
        f"👤 {name} (`{target_id}`)\n"
        f"👑 Роль: {role_name}\n\n"
        f"Включите/отключите нужные разрешения:\n\n"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    
    for perm_key, perm_name in PERMISSIONS.items():
        status = "✅" if current_perms.get(perm_key, False) else "❌"
        kb.add(types.InlineKeyboardButton(f"{status} {perm_name}", callback_data=f"toggle_perm_{target_id}_{perm_key}"))
    
    kb.add(types.InlineKeyboardButton("🔄 Сбросить к роли", callback_data=f"reset_perm_{target_id}"))
    kb.add(types.InlineKeyboardButton("🗑️ Удалить админа", callback_data=f"remove_admin_{target_id}"))
    kb.add(types.InlineKeyboardButton("🔙 Назад", callback_data="edit_admin_perms"))
    
    try:
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except Exception as e:
        print(f"[_redraw_admin_perms] Ошибка: {e}")

def _show_admin_logs(call):
    user_id = call.from_user.id
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT admin_name, action, target_name, details, created_at
            FROM admin_logs
            ORDER BY created_at DESC
            LIMIT 20
        """)
        logs = cur.fetchall()
    except Exception as e:
        print(f"[logs] Ошибка: {e}")
        bot.send_message(user_id, "❌ Ошибка получения логов")
        return
    finally:
        cur.close()
        return_db_connection(conn)
    
    if not logs:
        text = "📋 *Логи админов*\n\nПусто"
    else:
        text = "📋 *Последние 20 действий:*\n\n"
        for admin_name, action, target_name, details, created_at in logs:
            time_str = datetime.fromtimestamp(created_at).strftime("%d.%m %H:%M")
            target = f" → {target_name}" if target_name else ""
            text += f"🕐 {time_str} | *{admin_name}* {action}{target}\n"
            if details:
                text += f"  📎 {details}\n"
            text += "\n"
    
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        types.InlineKeyboardButton("🔄 Обновить", callback_data="admin_view_logs"),
        types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
    )
    
    try:
        if len(text) > 4000:
            text = text[:3950] + "\n…"
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=kb)
    except:
        bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

def show_autopost_menu(call_or_message, user_id):
    config = get_autopost_config()
    status = "✅ ВКЛ" if config['enabled'] else "❌ ВЫКЛ"
    last_post = int(get_setting('autopost_last_post', '0'))
    last_str = datetime.fromtimestamp(last_post).strftime("%d.%m в %H:%M") if last_post else "Не было"
    keys_count = len(get_keys_from_db())
    
    text = (
        f"📡 *АВТОПОСТИНГ*\n\n"
        f"📦 Ключей в базе: {keys_count}\n"
        f"📊 Статус: {status}\n"
        f"⏱ Интервал: {config['interval'] // 60} мин\n"
        f"📢 Канал: {config['channel_id']}\n"
        f"🕐 Последний пост: {last_str}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📥 Загрузить ключи", callback_data="autopost_load_keys"),
        types.InlineKeyboardButton("🚀 Начать" if not config['enabled'] else "⏹ Остановить", 
                                   callback_data="autopost_start" if not config['enabled'] else "autopost_stop"),
    )
    kb.add(
        types.InlineKeyboardButton("⚙️ Канал", callback_data="autopost_channel_settings"),
        types.InlineKeyboardButton("⏱ Интервал", callback_data="autopost_interval_settings"),
    )
    kb.add(types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel"))
    
    chat_id = call_or_message.message.chat.id if hasattr(call_or_message, 'message') else call_or_message.chat.id
    message_id = call_or_message.message.message_id if hasattr(call_or_message, 'message') else None
    
    if message_id:
        try:
            bot.edit_message_text(text, chat_id, message_id, parse_mode="Markdown", reply_markup=kb)
            return
        except:
            pass
    bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

def get_autopost_config():
    return {
        'enabled': get_setting('autopost_enabled', 'true') == 'true',
        'interval': int(get_setting('autopost_interval', '600')),
        'channel_id': int(get_setting('autopost_channel', '-1003668283208')),
    }

def save_autopost_config(config):
    set_setting('autopost_enabled', str(config['enabled']).lower())
    set_setting('autopost_interval', str(config['interval']))
    set_setting('autopost_channel', str(config['channel_id']))

# ==================== КОЛБЭКИ ПОЛЬЗОВАТЕЛЕЙ ====================

@bot.callback_query_handler(func=lambda call: call.data.startswith('filter_') or 
                             call.data.startswith('page_') or
                             call.data in ('back_to_list', 'close_manage'))
def callback_user_list_nav(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_users'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    data = call.data
    
    if data == 'close_manage':
        bot.answer_callback_query(call.id)
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        return
    
    if data == 'back_to_list':
        bot.answer_callback_query(call.id)
        with _cache_lock:
            cached = manage_cache.get(user_id, {})
            users = cached.get('users', [])
            filter_type = cached.get('filter', 'all')
        if not users:
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT user_id FROM users ORDER BY user_id")
                users = [row[0] for row in cur.fetchall()]
            finally:
                cur.close()
                return_db_connection(conn)
            with _cache_lock:
                manage_cache[user_id] = {
                    'users': users,
                    'filter': 'all',
                    'timestamp': int(time.time())
                }
        kb = build_user_list_keyboard(users, 0, filter_type)
        try:
            bot.edit_message_text(
                f"👥 Пользователи ({len(users)}):",
                call.message.chat.id, call.message.message_id,
                reply_markup=kb
            )
        except:
            pass
        return
    
    if data.startswith('page_'):
        parts = data.split('_')
        if len(parts) < 3:
            bot.answer_callback_query(call.id, "❌ Ошибка формата")
            return
        try:
            page = int(parts[1])
        except ValueError:
            bot.answer_callback_query(call.id, "❌ Ошибка формата")
            return
        filter_type = parts[2] if len(parts) > 2 else 'all'
        with _cache_lock:
            cached = manage_cache.get(user_id, {})
            users = cached.get('users', [])
        if not users:
            bot.answer_callback_query(call.id, "❌ Список устарел")
            return
        kb = build_user_list_keyboard(users, page, filter_type)
        try:
            bot.edit_message_reply_markup(
                call.message.chat.id, call.message.message_id,
                reply_markup=kb
            )
        except:
            pass
        bot.answer_callback_query(call.id)
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    current_time = int(time.time())
    try:
        if data == 'filter_active':
            cur.execute("""
                SELECT user_id FROM users 
                WHERE is_blocked = 0 AND subscription_end > %s 
                ORDER BY user_id
            """, (current_time,))
            filter_type = 'active'
        elif data == 'filter_inactive':
            cur.execute("""
                SELECT user_id FROM users 
                WHERE is_blocked = 0 AND (subscription_end IS NULL OR subscription_end <= %s)
                ORDER BY user_id
            """, (current_time,))
            filter_type = 'inactive'
        elif data == 'filter_admins':
            cur.execute("""
                SELECT u.user_id FROM users u
                INNER JOIN admins a ON u.user_id = a.user_id
                ORDER BY u.user_id
            """)
            filter_type = 'admins'
        else:
            cur.execute("SELECT user_id FROM users ORDER BY user_id")
            filter_type = 'all'
        
        users = [row[0] for row in cur.fetchall()]
    finally:
        cur.close()
        return_db_connection(conn)
    
    with _cache_lock:
        manage_cache[user_id] = {
            'users': users,
            'filter': filter_type,
            'timestamp': int(time.time())
        }
    
    kb = build_user_list_keyboard(users, 0, filter_type)
    try:
        bot.edit_message_text(
            f"👥 Пользователи ({len(users)}):",
            call.message.chat.id, call.message.message_id,
            reply_markup=kb
        )
    except:
        pass
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('user_') and len(call.data.split('_')) == 2)
def callback_user_detail(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "❌ Нет доступа.")
        return
    target_id = int(call.data.split('_')[1])
    if not has_permission(user_id, 'manage_users'):
        bot.answer_callback_query(call.id, "⛔️ У вас нет прав на управление пользователями.")
        return
    
    try:
        _refresh_user_card(call, target_id, user_id)
        bot.answer_callback_query(call.id)
    except Exception as e:
        print(f"[callback_user_detail] Ошибка: {e}")
        bot.answer_callback_query(call.id, "❌ Ошибка открытия карточки")

def _refresh_user_card(call, target_id, admin_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT 
                    COALESCE(subscription_end, 0) as subscription_end,
                    COALESCE(is_blocked, 0) as is_blocked
                FROM users WHERE user_id = %s
            """, (target_id,))
            row = cur.fetchone()
        finally:
            cur.close()
            return_db_connection(conn)

        if not row:
            bot.answer_callback_query(call.id, "❌ Пользователь не найден")
            return

        subscription_end, blk = row
        current_time = int(time.time())
        
        if blk == 1:
            status = "🚫 Заблокирован"
        elif subscription_end > 0 and subscription_end > current_time:
            days_left = (subscription_end - current_time) // 86400
            status = f"🟢 Активен ({days_left} дн)"
        else:
            status = "🔴 Неактивен"

        is_admin_user = is_admin(target_id)
        admin_text = "✅ Да" if is_admin_user else "❌ Нет"
        name = get_user_display_name(target_id)
        
        try:
            chat = bot.get_chat(target_id)
            username = f"@{chat.username}" if chat.username else "❌ Нет юзернейма"
        except:
            username = "❌ Не найден"

        text = f"""👤 *{name}*

🆔 ID: `{target_id}`
👤 Юзернейм: {username}
📊 Статус: {status}
👑 Админ: {admin_text}"""

        kb = types.InlineKeyboardMarkup(row_width=2)
        
        if has_permission(admin_id, 'add_days'):
            kb.add(types.InlineKeyboardButton("✅ Выдать подписку", callback_data=f"give_sub_{target_id}"))
            kb.add(types.InlineKeyboardButton("📅 +30 дн", callback_data=f"prolong_{target_id}_30"))
        
        if has_permission(admin_id, 'remove_days'):
            kb.add(types.InlineKeyboardButton("📅 -30 дн", callback_data=f"remove_days_{target_id}_30"))
        
        if has_permission(admin_id, 'add_days') or has_permission(admin_id, 'remove_days'):
            kb.add(types.InlineKeyboardButton("🗑️ Удалить подписку", callback_data=f"remove_sub_{target_id}"))
        
        if has_permission(admin_id, 'block_user'):
            if blk == 1:
                kb.add(types.InlineKeyboardButton("🔓 Разблокировать", callback_data=f"unblock_{target_id}"))
            else:
                kb.add(types.InlineKeyboardButton("🔒 Заблокировать", callback_data=f"block_{target_id}"))
        
        if has_permission(admin_id, 'manage_admins') and target_id not in OWNER_IDS:
            if is_admin_user:
                kb.add(types.InlineKeyboardButton("👑 Забрать админку", callback_data=f"remove_admin_{target_id}"))
            else:
                kb.add(types.InlineKeyboardButton("👑 Выдать админку", callback_data=f"grant_admin_{target_id}"))
        
        kb.row(
            types.InlineKeyboardButton("🔙 Назад к списку", callback_data="back_to_list"),
            types.InlineKeyboardButton("❌ Закрыть", callback_data="close_manage")
        )

        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except Exception as e:
        print(f"[refresh_card] Ошибка: {e}")
        bot.answer_callback_query(call.id, f"❌ Ошибка: {e}")

# ==================== АДМИН-ДЕЙСТВИЯ НАД ПОЛЬЗОВАТЕЛЯМИ ====================

@bot.callback_query_handler(func=lambda call: call.data.startswith('give_sub_'))
def callback_give_sub(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'add_days'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[2])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (target_id,))
        if not cur.fetchone():
            bot.answer_callback_query(call.id, "❌ Пользователь не найден.")
            return
        current_time = int(time.time())
        new_end = current_time + 30 * 24 * 60 * 60
        cur.execute("""
            UPDATE users SET 
                subscription_end = %s, 
                notified_3days = 0, 
                notified_expired = 0 
            WHERE user_id = %s
        """, (new_end, target_id))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Выдал подписку {target_id}", target_id=target_id, details="30 дней")
    bot.answer_callback_query(call.id, "✅ Выдана подписка на 30 дней!")
    try:
        bot.send_message(target_id, f"🎉 Администратор выдал вам подписку на 30 дней!")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('prolong_'))
def callback_prolong(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'add_days'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    parts = call.data.split('_')
    target_id = int(parts[1])
    days = int(parts[2])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Пользователь не найден.")
            return
        current_time = int(time.time())
        current_end = result[0] if (result[0] and result[0] > current_time) else current_time
        new_end = current_end + days * 24 * 60 * 60
        cur.execute("""
            UPDATE users SET 
                subscription_end = %s, 
                notified_3days = 0, 
                notified_expired = 0 
            WHERE user_id = %s
        """, (new_end, target_id))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Продлил подписку {target_id}", target_id=target_id, details=f"+{days} дней")
    bot.answer_callback_query(call.id, f"✅ Продлено на {days} дней!")
    try:
        bot.send_message(target_id, f"🎉 Ваша подписка продлена на {days} дней!")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('remove_days_'))
def callback_remove_days(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'remove_days'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    parts = call.data.split('_')
    target_id = int(parts[2])
    days = int(parts[3])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Пользователь не найден.")
            return
        current_time = int(time.time())
        current_end = result[0] if (result[0] and result[0] > current_time) else current_time
        new_end = current_end - days * 24 * 60 * 60
        if new_end < current_time:
            new_end = current_time - 1
        cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0 WHERE user_id = %s", (new_end, target_id))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Забрал дни у {target_id}", target_id=target_id, details=f"-{days} дней")
    bot.answer_callback_query(call.id, f"✅ Убавлено {days} дней!")
    try:
        bot.send_message(target_id, f"⚠️ Администратор забрал {days} дней подписки!")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('remove_sub_'))
def callback_remove_sub(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'add_days'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[2])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET subscription_end = %s WHERE user_id = %s", (int(time.time()) - 1, target_id))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Удалил подписку у {target_id}", target_id=target_id)
    bot.answer_callback_query(call.id, "✅ Подписка удалена!")
    try:
        bot.send_message(target_id, "❌ Ваша подписка была удалена администратором.")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('block_'))
def callback_block(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'block_user'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[1])
    if target_id in OWNER_IDS:
        bot.answer_callback_query(call.id, "❌ Нельзя заблокировать владельца.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET is_blocked = 1 WHERE user_id = %s", (target_id,))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Заблокировал {target_id}", target_id=target_id)
    bot.answer_callback_query(call.id, "✅ Пользователь заблокирован!")
    try:
        bot.send_message(target_id, f"🚫 Вы заблокированы администратором.\n\nОбратитесь: @severny_3d или @mel1ste")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('unblock_'))
def callback_unblock(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'unblock_user'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[1])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET is_blocked = 0 WHERE user_id = %s", (target_id,))
        conn.commit()
        clear_user_cache(target_id)
    finally:
        cur.close()
        return_db_connection(conn)
    
    log_admin_action(user_id, f"Разблокировал {target_id}", target_id=target_id)
    bot.answer_callback_query(call.id, "✅ Пользователь разблокирован!")
    try:
        bot.send_message(target_id, "✅ Вы разблокированы!")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('grant_admin_'))
def callback_grant_admin(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_admins'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[2])
    if target_id in OWNER_IDS:
        bot.answer_callback_query(call.id, "❌ Это владелец.")
        return
    if is_admin(target_id):
        bot.answer_callback_query(call.id, "❌ Уже админ.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (target_id,))
        if not cur.fetchone():
            bot.answer_callback_query(call.id, "❌ Пользователь не зарегистрирован.")
            return
        
        role = 'junior'
        perms = ROLE_PRESETS[role]['permissions'].copy()
        cur.execute("""
            INSERT INTO admins (user_id, role, permissions, added_by, added_at) 
            VALUES (%s, %s, %s, %s, %s)
        """, (target_id, role, json.dumps(perms), user_id, int(time.time())))
        conn.commit()
    except Exception as e:
        conn.rollback()
        bot.answer_callback_query(call.id, f"❌ Ошибка: {e}")
        return
    finally:
        cur.close()
        return_db_connection(conn)
    
    name = get_user_display_name(target_id)
    log_admin_action(user_id, f"Назначил админом {target_id}", target_id=target_id, details=f"Роль: {role}")
    bot.answer_callback_query(call.id, f"✅ {name} назначен админом!")
    try:
        bot.send_message(target_id, "👑 Вам назначена роль администратора!\n\nТеперь вы имеете доступ к админ-панели (/admin)")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('remove_admin_'))
def callback_remove_admin(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_admins'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    target_id = int(call.data.split('_')[2])
    if target_id in OWNER_IDS:
        bot.answer_callback_query(call.id, "❌ Нельзя удалить владельца.")
        return
    if not is_admin(target_id):
        bot.answer_callback_query(call.id, "❌ Не админ.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM admins WHERE user_id = %s", (target_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        bot.answer_callback_query(call.id, f"❌ Ошибка: {e}")
        return
    finally:
        cur.close()
        return_db_connection(conn)
    
    name = get_user_display_name(target_id)
    log_admin_action(user_id, f"Удалил админа {target_id}", target_id=target_id)
    bot.answer_callback_query(call.id, f"✅ У {name} отозваны права администратора!")
    try:
        bot.send_message(target_id, "❌ Ваши права администратора были отозваны.")
    except:
        pass
    _refresh_user_card(call, target_id, user_id)

# ==================== ТОГГЛ ПЕРМИШЕНОВ ====================

@bot.callback_query_handler(func=lambda call: call.data.startswith('toggle_perm_'))
def callback_toggle_perm(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_admins'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    parts = call.data.split('_')
    if len(parts) < 4:
        bot.answer_callback_query(call.id, "❌ Ошибка формата")
        return
    target_id = int(parts[2])
    perm_key = '_'.join(parts[3:])
    
    if target_id in OWNER_IDS:
        bot.answer_callback_query(call.id, "❌ Нельзя редактировать владельца.")
        return
    
    current_perms = get_admin_permissions(target_id)
    current_perms[perm_key] = not current_perms.get(perm_key, False)
    update_admin_permissions(target_id, current_perms)
    
    log_admin_action(user_id, f"Изменил право {perm_key} у {target_id}", 
                     target_id=target_id,
                     details=f"{'вкл' if current_perms[perm_key] else 'выкл'}")
    
    bot.answer_callback_query(call.id, 
        "✅ Включено" if current_perms[perm_key] else "❌ Выключено")
    _redraw_admin_perms(call, target_id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('reset_perm_'))
def callback_reset_perm(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_admins'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    parts = call.data.split('_')
    if len(parts) < 3:
        bot.answer_callback_query(call.id, "❌ Ошибка формата")
        return
    target_id = int(parts[2])
    
    if target_id in OWNER_IDS:
        bot.answer_callback_query(call.id, "❌ Нельзя сбрасывать права владельца.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT role FROM admins WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
    finally:
        cur.close()
        return_db_connection(conn)
    
    if not result:
        bot.answer_callback_query(call.id, "❌ Админ не найден")
        return
    
    role = result[0] or 'junior'
    default_perms = ROLE_PRESETS.get(role, ROLE_PRESETS['junior'])['permissions'].copy()
    update_admin_permissions(target_id, default_perms)
    log_admin_action(user_id, f"Сбросил права {target_id} к роли {role}", target_id=target_id)
    bot.answer_callback_query(call.id, f"✅ Права сброшены к роли {role}")
    _redraw_admin_perms(call, target_id)

# ==================== АДМИН-КОМАНДЫ ====================

@bot.message_handler(commands=['check'])
def cmd_check_user(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'check_user'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /check [ID или @username]", parse_mode="Markdown")
        return
    target_input = parts[1].strip()
    target_id = get_user_id_from_input(target_input)
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{target_input}`")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end, is_blocked, token FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Не найден")
            return
        sub_end, blocked, token = result
        current_time = int(time.time())
        status = "🚫 Заблокирован" if blocked else ("✅ Активен" if sub_end > current_time else "❌ Неактивен")
        text = f"📋 *Проверка*\n🆔 ID: `{target_id}`\n📊 Статус: {status}\n🔗 Токен: `{token}`"
        log_admin_action(user_id, f"Проверил пользователя {target_id}", target_id=target_id)
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['user'])
def cmd_user_info(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'user_info'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /user [ID или @username]", parse_mode="Markdown")
        return
    target_input = parts[1].strip()
    target_id = get_user_id_from_input(target_input)
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{target_input}`")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end, is_blocked, token, last_activity FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Не найден")
            return
        sub_end, blocked, token, last_act = result
        current_time = int(time.time())
        status = "🚫 Заблокирован" if blocked else ("✅ Активен" if sub_end > current_time else "❌ Неактивен")
        name = get_user_display_name(target_id)
        last_act_str = datetime.fromtimestamp(last_act).strftime("%d.%m.%Y %H:%M") if last_act else "Нет"
        text = f"""👤 *{name}*
🆔 ID: `{target_id}`
📊 Статус: {status}
📅 Подписка до: {datetime.fromtimestamp(sub_end).strftime('%d.%m.%Y') if sub_end else 'Нет'}
🕐 Активность: {last_act_str}"""
        log_admin_action(user_id, f"Посмотрел инфо о {target_id}", target_id=target_id)
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['add_days'])
def cmd_add_days(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'add_days'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /add_days [ID или @username] [дни]", parse_mode="Markdown")
        return
    args = parts[1].strip().split()
    if len(args) < 2:
        bot.reply_to(message, "❌ /add_days [ID или @username] [дни]", parse_mode="Markdown")
        return
    target_id = get_user_id_from_input(args[0])
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{args[0]}`")
        return
    try:
        days = int(args[1])
    except:
        bot.reply_to(message, "❌ Дни должны быть числом")
        return
    if days < 1:
        bot.reply_to(message, "❌ Количество дней должно быть больше 0.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Не найден")
            return
        current_time = int(time.time())
        current_end = result[0] if (result[0] and result[0] > current_time) else current_time
        new_end = current_end + days * 24 * 60 * 60
        cur.execute("""
            UPDATE users SET 
                subscription_end = %s, 
                notified_3days = 0, 
                notified_expired = 0 
            WHERE user_id = %s
        """, (new_end, target_id))
        conn.commit()
        clear_user_cache(target_id)
        log_admin_action(user_id, f"Выдал {days} дней {target_id}", target_id=target_id)
        bot.reply_to(message, f"✅ +{days} дней")
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка: {e}")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['remove_days'])
def cmd_remove_days(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'remove_days'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /remove_days [ID или @username] [дни]", parse_mode="Markdown")
        return
    args = parts[1].strip().split()
    if len(args) < 2:
        bot.reply_to(message, "❌ /remove_days [ID или @username] [дни]", parse_mode="Markdown")
        return
    target_id = get_user_id_from_input(args[0])
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{args[0]}`")
        return
    try:
        days = int(args[1])
    except:
        bot.reply_to(message, "❌ Дни должны быть числом")
        return
    if days < 1:
        bot.reply_to(message, "❌ Количество дней должно быть больше 0.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Не найден")
            return
        current_time = int(time.time())
        current_end = result[0] if (result[0] and result[0] > current_time) else current_time
        new_end = current_end - days * 24 * 60 * 60
        if new_end < current_time:
            new_end = current_time - 1
        cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0 WHERE user_id = %s", (new_end, target_id))
        conn.commit()
        clear_user_cache(target_id)
        log_admin_action(user_id, f"Забрал {days} дней у {target_id}", target_id=target_id)
        bot.reply_to(message, f"✅ -{days} дней")
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка: {e}")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['block'])
def cmd_block_user(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'block_user'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /block [ID или @username]", parse_mode="Markdown")
        return
    target_input = parts[1].strip()
    target_id = get_user_id_from_input(target_input)
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{target_input}`")
        return
    if target_id in OWNER_IDS:
        bot.reply_to(message, "❌ Нельзя заблокировать владельца.")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET is_blocked = 1 WHERE user_id = %s", (target_id,))
        conn.commit()
        clear_user_cache(target_id)
        log_admin_action(user_id, f"Заблокировал {target_id}", target_id=target_id)
        bot.reply_to(message, f"🚫 Заблокирован {target_id}")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['unblock'])
def cmd_unblock_user(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'unblock_user'):
        return
    text = message.text.strip()
    parts = text.split(None, 1)
    if len(parts) < 2:
        bot.reply_to(message, "❌ /unblock [ID или @username]", parse_mode="Markdown")
        return
    target_input = parts[1].strip()
    target_id = get_user_id_from_input(target_input)
    if not target_id:
        bot.reply_to(message, f"❌ Неверный ID: `{target_input}`")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET is_blocked = 0 WHERE user_id = %s", (target_id,))
        conn.commit()
        clear_user_cache(target_id)
        log_admin_action(user_id, f"Разблокировал {target_id}", target_id=target_id)
        bot.reply_to(message, f"✅ Разблокирован {target_id}")
    finally:
        cur.close()
        return_db_connection(conn)

@bot.message_handler(commands=['logs'])
def cmd_view_logs(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'view_logs'):
        bot.reply_to(message, "⛔️ Нет прав")
        return
    
    text = message.text.strip()
    parts = text.split(None, 1)
    limit = 20
    if len(parts) > 1:
        try:
            limit = int(parts[1])
            if limit > 100:
                limit = 100
        except:
            pass
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT admin_name, action, target_name, details, created_at
            FROM admin_logs
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        logs = cur.fetchall()
    finally:
        cur.close()
        return_db_connection(conn)
    
    if not logs:
        bot.reply_to(message, "📋 *Логи админов*\n\nПусто", parse_mode="Markdown")
        return
    
    text = f"📋 *Последние {len(logs)} действий:*\n\n"
    for admin_name, action, target_name, details, created_at in logs:
        time_str = datetime.fromtimestamp(created_at).strftime("%d.%m %H:%M")
        target = f" → {target_name}" if target_name else ""
        text += f"🕐 {time_str} | *{admin_name}* {action}{target}\n"
        if details:
            text += f"  📎 {details}\n"
        text += "\n"
    
    if len(text) > 4000:
        text = text[:3950] + "\n…"
    
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(commands=['cancel'])
def cmd_cancel(message):
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    cleared = False
    with _cache_lock:
        if user_id in announce_data:
            del announce_data[user_id]
            cleared = True
        if user_id in keys_loading:
            del keys_loading[user_id]
            cleared = True
    if cleared:
        bot.reply_to(message, "✅ Отменено.")
    else:
        bot.reply_to(message, "❌ Нет активных режимов.")

# ==================== КЛЮЧИ (АДМИН) ====================

def show_keys_menu(user_id, chat_id, message_id):
    keys = get_keys_from_db()
    sub_keys = get_subscription_keys_from_db()
    total_issued = int(get_setting('total_keys_issued', '0'))
    
    text = (
        f"🔑 *Управление ключами*\n\n"
        f"📋 *Подписка /sub:* {len(sub_keys)} ключей\n"
        f"📦 Всего ключей: {len(keys)}\n"
        f"🗑️ Выдано ключей: {total_issued}\n\n"
        f"Выберите действие:"
    )
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📥 Ключи подписки", callback_data="admin_sub_keys_load"),
        types.InlineKeyboardButton("🧹 Очистить нерабочие", callback_data="admin_keys_clean_dead")
    )
    kb.add(
        types.InlineKeyboardButton("🗑️ Очистить ВСЕ", callback_data="admin_keys_clear_all"),
        types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
    )
    
    sent = False
    if message_id:
        try:
            bot.edit_message_text(text, chat_id, message_id, parse_mode="Markdown", reply_markup=kb)
            sent = True
        except Exception as e:
            print(f"[show_keys_menu] edit failed: {e}")
    if not sent:
        bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=kb)

def callback_admin_keys_load(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    bot.answer_callback_query(call.id, "📥 Отправьте ключи")
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("✅ Завершить", callback_data="admin_keys_load_finish"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="admin_keys_load_cancel")
    )
    msg = bot.send_message(
        user_id,
        "📥 *Загрузка ключей подписки*\n\n"
        "Отправляйте ключи, затем нажмите ✅ Завершить",
        parse_mode="Markdown",
        reply_markup=kb
    )
    with _cache_lock:
        keys_loading[user_id] = {
            'keys': [], 'mode': 'subscription',
            'message_id': msg.message_id,
            'timestamp': int(time.time())
        }

def callback_admin_keys_load_finish(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    with _cache_lock:
        if user_id not in keys_loading:
            bot.answer_callback_query(call.id, "❌ Нет активной загрузки")
            return
        session = keys_loading[user_id]
        keys = session['keys']
        mode = session.get('mode', 'subscription')
        del keys_loading[user_id]
    if not keys:
        bot.answer_callback_query(call.id, "❌ Нет ключей")
        return
    
    if mode == 'subscription':
        save_subscription_keys_to_db(keys)
    else:
        save_keys_to_db(keys)
    
    log_admin_action(user_id, f"Загрузил {len(keys)} ключей ({mode})", details=f"Ключей: {len(keys)}")
    bot.answer_callback_query(call.id, f"✅ Загружено {len(keys)} ключей!")
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

def callback_admin_keys_load_cancel(call):
    user_id = call.from_user.id
    with _cache_lock:
        if user_id in keys_loading:
            del keys_loading[user_id]
    bot.answer_callback_query(call.id, "❌ Отменено")
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except:
        pass
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

def callback_admin_keys_clean_dead(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    keys = get_keys_from_db()
    if not keys:
        bot.answer_callback_query(call.id, "❌ Нет ключей для проверки")
        return
    bot.answer_callback_query(call.id, "⏳ Проверяю ключи...")
    alive_keys = []
    dead_keys = []
    for key in keys:
        match = re.search(r'@([\d\.]+):(\d+)', key)
        if match:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((match.group(1), int(match.group(2))))
                sock.close()
                if result == 0:
                    alive_keys.append(key)
                else:
                    dead_keys.append(key)
            except:
                dead_keys.append(key)
        else:
            dead_keys.append(key)
    save_keys_to_db(alive_keys)
    log_admin_action(user_id, f"Очистил нерабочие ключи", details=f"Удалено: {len(dead_keys)}, осталось: {len(alive_keys)}")
    text = (
        f"🧹 *Очистка нерабочих ключей завершена!*\n\n"
        f"✅ Оставлено живых: {len(alive_keys)}\n"
        f"🗑️ Удалено нерабочих: {len(dead_keys)}\n"
        f"📦 Всего в базе: {len(alive_keys)}"
    )
    try:
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown")
    except:
        bot.send_message(user_id, text, parse_mode="Markdown")
    time.sleep(2)
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

def callback_admin_keys_clear_all(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    bot.answer_callback_query(call.id)
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("✅ Да, удалить все", callback_data="admin_keys_clear_confirm"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="admin_keys_back")
    )
    try:
        bot.edit_message_text(
            "⚠️ *ВНИМАНИЕ!*\n\n"
            "Вы уверены, что хотите удалить ВСЕ ключи?\n"
            "Это действие НЕЛЬЗЯ будет отменить!",
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except:
        bot.send_message(user_id, "⚠️ Подтвердите удаление всех ключей.", reply_markup=kb)

def callback_admin_keys_clear_confirm(call):
    user_id = call.from_user.id
    if not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    sub_count = len(get_subscription_keys_from_db())
    save_keys_to_db([])
    save_subscription_keys_to_db([])
    set_setting('total_keys_issued', '0')
    log_admin_action(user_id, f"Удалил все ключи", details=f"Подписка: {sub_count}")
    bot.answer_callback_query(call.id, f"🗑️ Удалено {sub_count} ключей!")
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

def callback_admin_keys_back(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id)
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

# ==================== ОБРАБОТКА PRIVATE СООБЩЕНИЙ ====================

@bot.message_handler(func=lambda m: m.chat.type == 'private' and not (m.text or '').startswith('/'))
def handle_private_messages(message):
    user_id = message.from_user.id
    text = message.text or ''

    if message.from_user.username:
        pass

    if text in ["👤 Личный кабинет", "📡 Моя подписка", "👥 Рефералы", "🏆 Топ рефералов", "ℹ️ Стаж бота", "📋 Правила", "❓ Поддержка"]:
        return

    with _cache_lock:
        in_announce = user_id in announce_data
        in_keys_loading = user_id in keys_loading

    if in_announce:
        admin_announce_text(message)
        return

    if in_keys_loading:
        raw = text or message.caption or ''
        found_keys = []
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and ('://' in line):
                    found_keys.append(line)
        if not found_keys and message.document:
            try:
                file = bot.get_file(message.document.file_id)
                data_bytes = bot.download_file(file.file_path)
                content = data_bytes.decode('utf-8', errors='ignore')
                for line in content.splitlines():
                    line = line.strip()
                    if line and ('://' in line):
                        found_keys.append(line)
            except:
                pass
        if found_keys:
            with _cache_lock:
                if user_id in keys_loading:
                    keys_loading[user_id]['keys'].extend(found_keys)
                    keys_loading[user_id]['keys'] = list(dict.fromkeys(keys_loading[user_id]['keys']))
                    keys_loading[user_id]['timestamp'] = int(time.time())
                    total = len(keys_loading[user_id]['keys'])
            bot.reply_to(message, f"✅ Загружено {len(found_keys)}. Всего: {total}")
        else:
            bot.reply_to(message, "❌ Ключи не найдены.")
        return

    if text:
        bot.reply_to(message, "Используйте кнопки меню или /cancel для отмены.", reply_markup=main_menu())

def admin_announce_text(message):
    user_id = message.from_user.id
    with _cache_lock:
        if user_id not in announce_data:
            return
        data = announce_data.pop(user_id, {})
    
    announce_type = data.get('type', 'dm')
    text = message.text
    caption = message.caption or ''
    
    if announce_type == 'dm':
        if not text and not message.photo and not message.video and not message.document:
            bot.reply_to(message, "❌ Отправьте текст или медиа.")
            return
        
        def do_announce():
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT user_id FROM users")
                users = cur.fetchall()
            finally:
                cur.close()
                return_db_connection(conn)
            sent = 0
            for (uid,) in users:
                try:
                    if is_blocked(uid):
                        continue
                    if message.photo:
                        bot.send_photo(uid, message.photo[-1].file_id, caption=caption)
                    elif message.video:
                        bot.send_video(uid, message.video.file_id, caption=caption)
                    elif message.document:
                        bot.send_document(uid, message.document.file_id, caption=caption)
                    else:
                        bot.send_message(uid, text)
                    sent += 1
                    time.sleep(0.05)
                except:
                    pass
            log_admin_action(user_id, f"Сделал рассылку в ЛС", details=f"Отправлено: {sent} пользователей")
            try:
                bot.send_message(user_id, f"✅ Отправлено {sent} пользователям")
            except:
                pass
        
        bot.reply_to(message, "⏳ Рассылка запущена в фоне...")
        t = Thread(target=do_announce, daemon=True)
        t.start()

# ==================== ФЛАСК ====================

@app.route('/')
def index():
    return "VPN Bot is running!"

@app.route('/ping')
def ping():
    return "OK", 200

@app.route('/health')
def health():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return_db_connection(conn)
        return "OK", 200
    except:
        return "DB Error", 500

@app.route('/sub/<token>')
def subscription(token):
    if not token:
        return "Invalid token", 400
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id, subscription_end, is_frozen, is_blocked FROM users WHERE token = %s", (token,))
        result = cur.fetchone()
        if not result:
            return "Invalid token", 404
        user_id, sub_end, is_frozen, is_blocked = result
        
        if is_blocked:
            return "User blocked", 403
        
        current_time = int(time.time())
        
        if is_frozen:
            content = KEY_TEMPLATE.format(
                expire=int(time.time()),
                keys='# Подписка заморожена'
            )
            return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        
        if not sub_end or sub_end < current_time:
            return "Subscription expired", 403
        
        try:
            cur.execute("UPDATE users SET last_activity = %s WHERE user_id = %s", (int(time.time()), user_id))
            conn.commit()
        except Exception as e:
            print(f"[sub] Ошибка обновления активности: {e}")
            try:
                conn.rollback()
            except:
                pass
        
        keys = get_subscription_keys_from_db()
        if not keys:
            keys = get_keys_from_db()
        if not keys:
            keys = DEFAULT_KEYS
        expire_timestamp = sub_end
        content = KEY_TEMPLATE.format(expire=expire_timestamp, keys='\n'.join(keys))
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    finally:
        cur.close()
        return_db_connection(conn)

# ==================== ЗАПУСК ====================

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN не задан!")
        sys.exit(1)
    if not DATABASE_URL:
        print("❌ DATABASE_URL не задан!")
        sys.exit(1)
    
    port = int(os.getenv('PORT', 5000))
    
    def delayed_start():
        print("🚀 Запуск бота...")
        init_db_pool()
        
        try:
            init_db()
            print("✅ База данных инициализирована")
        except Exception as e:
            print(f"❌ Ошибка БД: {e}")
            sys.exit(1)
        
        ensure_bot_start_time()
        
        try:
            bot.set_my_commands([
                types.BotCommand("start", "Запустить бота"),
                types.BotCommand("admin", "Админ-панель"),
                types.BotCommand("ref", "Реферальная ссылка"),
                types.BotCommand("cancel", "Отменить режим"),
            ])
        except Exception as e:
            print(f"[set_commands] Ошибка: {e}")
        
        while True:
            try:
                bot.delete_webhook(drop_pending_updates=True)
                time.sleep(1)
                bot.infinity_polling(
                    timeout=30,
                    long_polling_timeout=30,
                    skip_pending=True,
                    allowed_updates=['message', 'callback_query']
                )
            except Exception as e:
                err = str(e)
                if '409' in err:
                    print(f"⚠️ Конфликт. Ждём 30 сек...")
                    time.sleep(30)
                else:
                    print(f"❌ Polling ошибка: {e}")
                    time.sleep(10)
    
    Thread(target=delayed_start, daemon=True).start()
    
    print(f"📡 Flask на порту {port}...")
    serve(app, host='0.0.0.0', port=port)
