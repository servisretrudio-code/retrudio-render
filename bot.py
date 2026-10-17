import asyncio
import sqlite3
import os
import logging
import random
import string
import html
import json
import hashlib
from dotenv import load_dotenv
from datetime import datetime, timedelta
from aiogram import BaseMiddleware, Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    Message, LabeledPrice, PreCheckoutQuery, ReplyKeyboardRemove, FSInputFile,
    InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery,
)
from werkzeug.security import check_password_hash, generate_password_hash

# Включаем логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)
load_dotenv()

# --- НАСТРОЙКИ ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
try:
    SUBSCRIPTION_PRICE = int(os.getenv("SUBSCRIPTION_PRICE", "0"))
except ValueError:
    SUBSCRIPTION_PRICE = 0
SITE_URL = os.getenv("SITE_URL", "https://retrudio.space")

# Список ID администраторов
ADMIN_IDS = [5025390367, 8221414112]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
PROUSER_PATH = os.path.join(BASE_DIR, "prouser.json")  # необработанные платежи
SCHEMS_DIR = os.path.join(BASE_DIR, "Schems")

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.getenv("DB_PATH") or os.path.join(DATA_DIR, "app.db")

# Защита от брутфорса: {telegram_id: {"attempts": int, "blocked_until": datetime}}
_login_attempts: dict = {}
MAX_ATTEMPTS = 5          
BLOCK_DURATION_MIN = 15   
# -----------------

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN не задан. Добавьте его в файл .env: BOT_TOKEN=123456:ABC...")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()


def esc(value) -> str:
    """Экранирование пользовательских данных для HTML parse_mode."""
    return html.escape(str(value))


class AuthStates(StatesGroup):
    waiting_for_login = State()
    waiting_for_password = State()


class ChangePasswordStates(StatesGroup):
    waiting_for_old_password = State()
    waiting_for_new_password = State()
    waiting_for_confirm_password = State()


# --- Инициализация базы данных и новых колонок статусов ---
def init_db_columns():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if "telegram_id" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN telegram_id INTEGER")
        if "status" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
        if "banned_until" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN banned_until TEXT")
        if "ban_reason" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN ban_reason TEXT")
        if "is_admin" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")

        # Все, кто хоть раз писал боту (в том числе без регистрации на сайте) — для рассылки
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS bot_chats ("
            "telegram_id INTEGER PRIMARY KEY, "
            "first_seen TEXT)"
        )

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка инициализации колонок БД: {e}")


def register_chat(tg_id: int):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO bot_chats (telegram_id, first_seen) VALUES (?, ?)",
            (tg_id, datetime.utcnow().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


class TrackChatsMiddleware(BaseMiddleware):
    """Запоминает каждого, кто написал боту в личку (например /start), чтобы ему доходила рассылка."""

    async def __call__(self, handler, event, data):
        try:
            if event.chat.type == "private" and event.from_user:
                register_chat(event.from_user.id)
        except Exception as e:
            logger.warning(f"Не удалось запомнить чат: {e}")
        return await handler(event, data)


dp.message.outer_middleware(TrackChatsMiddleware())


def is_admin(tg_id: int) -> bool:
    if tg_id in ADMIN_IDS:
        return True
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE telegram_id = ?", (tg_id,))
        row = cursor.fetchone()
        conn.close()
        return bool(row and row[0] == 1)
    except Exception:
        return False


def is_blocked_brute(tg_id: int) -> tuple[bool, int]:
    info = _login_attempts.get(tg_id)
    if not info:
        return False, 0
    if info.get("blocked_until") and datetime.utcnow() < info["blocked_until"]:
        remaining = (info["blocked_until"] - datetime.utcnow()).seconds // 60 + 1
        return True, remaining
    return False, 0


def record_failed_attempt(tg_id: int) -> int:
    if tg_id not in _login_attempts:
        _login_attempts[tg_id] = {"attempts": 0, "blocked_until": None}

    _login_attempts[tg_id]["attempts"] += 1
    attempts = _login_attempts[tg_id]["attempts"]

    if attempts >= MAX_ATTEMPTS:
        _login_attempts[tg_id]["blocked_until"] = datetime.utcnow() + timedelta(minutes=BLOCK_DURATION_MIN)
        _login_attempts[tg_id]["attempts"] = 0
        return 0

    return MAX_ATTEMPTS - attempts


def reset_attempts(tg_id: int):
    if tg_id in _login_attempts:
        del _login_attempts[tg_id]


# --- Пользовательские команды ---

@dp.message(Command("start"))
async def cmd_start(message: Message):
    docs_path = os.path.join(SCHEMS_DIR, "docs.html")
    rules_path = os.path.join(SCHEMS_DIR, "rules.html")
    caption_text = (
        "📜 <b>Ознакомьтесь с правилами сервиса.</b>\n\n"
        "Если вы согласны с условиями использования, "
        "войдите в аккаунт командой: /login\n\n"
        "📋 Список команд: /help"
    )
    
    has_docs = os.path.exists(docs_path)
    has_rules = os.path.exists(rules_path)

    if has_docs and has_rules:
        # Если есть оба файла: первый отправляем без подписи, второй с подписью
        await message.answer_document(document=FSInputFile(docs_path))
        await message.answer_document(document=FSInputFile(rules_path), caption=caption_text)
    elif has_rules:
        # Если есть только rules.html
        await message.answer_document(document=FSInputFile(rules_path), caption=caption_text)
    elif has_docs:
        # Если есть только docs.html (теперь подпись не потеряется!)
        await message.answer_document(document=FSInputFile(docs_path), caption=caption_text)
    else:
        # Если вообще ничего нет
        await message.answer("⚠️ Файлы с правилами не найдены.\n\n" + caption_text)

@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "📋 <b>Список команд:</b>\n\n"
        "/start — начало работы\n"
        "/login — войти в аккаунт\n"
        "/buy — купить подписку (30 дней)\n"
        "/status — проверить статус подписки\n"
        "/change_password — сменить пароль\n"
        "/stop_subscription — отменить подписку\n"
        "/support — написать в поддержку\n"
        "/help — это сообщение"
    )


@dp.message(Command("status"))
async def cmd_status(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")

    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, subscription_until FROM users WHERE id=?", (user_id_db,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            await message.answer("❌ Пользователь не найден.")
            return

        username, email, sub_until = user
        now = datetime.utcnow()

        if sub_until:
            sub_dt = datetime.fromisoformat(sub_until)
            if sub_dt > now:
                days_left = (sub_dt - now).days
                status_text = f"✅ <b>Активна</b> до <code>{sub_until[:10]}</code> (осталось {days_left} дн.)"
            else:
                status_text = "❌ <b>Истекла</b>"
        else:
            status_text = "❌ <b>Нет подписки</b>"

        await message.answer(
            f"👤 <b>Аккаунт:</b>\n"
            f"• Имя: <code>{esc(username or '—')}</code>\n"
            f"• Email: <code>{esc(email or '—')}</code>\n\n"
            f"⭐ <b>Подписка:</b> {status_text}\n\n"
            f"Купить/продлить: /buy"
        )
    except Exception as e:
        logger.error(f"Ошибка /status: {e}")
        logger.error(f"Ошибка: {e}")
        await message.answer("⚠️ Произошла ошибка. Попробуйте позже.")


# --- Авторизация и проверка статусов банов ---

@dp.message(Command("login"))
async def cmd_login(message: Message, state: FSMContext):
    tg_id = message.from_user.id
    blocked, mins = is_blocked_brute(tg_id)
    if blocked:
        await message.answer(f"🚫 <b>Слишком много неудачных попыток.</b>\nПовторите через {mins} мин.")
        return

    await message.answer(
        "🔐 <b>Авторизация</b>\n\nВведите ваш <b>логин</b> или email от сайта:",
        reply_markup=ReplyKeyboardRemove(),
    )
    await state.set_state(AuthStates.waiting_for_login)


@dp.message(AuthStates.waiting_for_login, F.text, ~F.text.startswith("/"))
async def process_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text)
    await message.answer("🔑 Введите ваш <b>пароль</b>:")
    await state.set_state(AuthStates.waiting_for_password)


@dp.message(AuthStates.waiting_for_password, F.text)
async def process_password(message: Message, state: FSMContext):
    tg_id = message.from_user.id

    if message.text.startswith("/"):
        await message.answer("⚠️ Завершите авторизацию — введите пароль.")
        return

    try:
        await message.delete()
    except Exception:
        pass

    blocked, mins = is_blocked_brute(tg_id)
    if blocked:
        await state.clear()
        await message.answer(f"🚫 <b>Слишком много неудачных попыток.</b>\nПовторите через {mins} мин.")
        return

    password = message.text
    data = await state.get_data()
    login = data.get("login")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, status, banned_until, ban_reason FROM users WHERE email = ? OR username = ?",
            (login, login),
        )
        user = cursor.fetchone()

        if user:
            user_id_db, username_db, password_hash, status, banned_until, ban_reason = user
            
            # Проверка статуса BANNED / PERM_BANNED
            if status == 'perm_banned':
                conn.close()
                await state.clear()
                await message.answer(f"🚫 <b>Ваш аккаунт заблокирован навсегда.</b>\nПричина: {esc(ban_reason or 'Нарушение правил')}")
                return
            elif status == 'banned' and banned_until:
                banned_dt = datetime.fromisoformat(banned_until)
                if banned_dt > datetime.utcnow():
                    conn.close()
                    await state.clear()
                    await message.answer(f"🚫 <b>Ваш аккаунт заблокирован.</b>\nСрок: до {banned_until[:16]}\nПричина: {esc(ban_reason or 'Нарушение правил')}")
                    return
                else:
                    cursor.execute("UPDATE users SET status='active', banned_until=NULL, ban_reason=NULL WHERE id=?", (user_id_db,))
                    conn.commit()

            display_name = username_db if username_db else "Пользователь"

            if check_password_hash(password_hash, password) or password == password_hash:
                reset_attempts(tg_id)
                cursor.execute("UPDATE users SET telegram_id=? WHERE id=?", (tg_id, user_id_db))
                conn.commit()
                conn.close()
                
                await state.clear()
                await state.update_data(user_id_db=user_id_db)
                await message.answer(
                    f"✅ <b>Вход выполнен!</b>\n"
                    f"Привет, {esc(display_name)}!\n\n"
                    f"• Статус подписки: /status\n"
                    f"• Купить подписку: /buy\n"
                    f"• Сменить пароль: /change_password"
                )
            else:
                conn.close()
                remaining = record_failed_attempt(tg_id)
                if remaining == 0:
                    await state.clear()
                    await message.answer(f"🚫 <b>Превышен лимит попыток.</b>\nАккаунт заблокирован на {BLOCK_DURATION_MIN} мин.")
                else:
                    await message.answer(f"❌ Неверный пароль. Осталось попыток: {remaining}\nПопробуйте снова: /login")
                    await state.clear()
        else:
            conn.close()
            record_failed_attempt(tg_id)
            await message.answer("❌ Пользователь не найден. Попробуйте снова: /login")
            await state.clear()

    except Exception as e:
        logger.error(f"Ошибка авторизации: {e}")
        logger.error(f"Ошибка: {e}")
        await message.answer("⚠️ Произошла ошибка. Попробуйте позже.")
        await state.clear()


# --- Оплата и прочие команды ---

@dp.message(Command("buy"))
async def cmd_buy(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")

    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return

    if SUBSCRIPTION_PRICE <= 0:
        logger.error("SUBSCRIPTION_PRICE не задан или некорректен в .env")
        await message.answer("⚠️ Оплата временно недоступна.")
        return

    prices = [LabeledPrice(label="Подписка (30 дней)", amount=SUBSCRIPTION_PRICE)]
    await message.answer_invoice(
        title="Оплата PRO-тарифа",
        description="Подписка на сайт сроком на 30 дней.",
        payload=f"sub_user_{user_id_db}",
        currency="XTR",
        prices=prices,
        provider_token="",
    )


@dp.pre_checkout_query()
async def process_pre_checkout(pre_checkout_query: PreCheckoutQuery):
    await pre_checkout_query.answer(ok=True)


# --- Необработанные платежи: prouser.json ---
# Формат записи: {"id_PAYMENT": "...", "user_email": "...", "status": "anticipation" | "success"}

def get_admin_ids() -> set:
    ids = set(ADMIN_IDS)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT telegram_id FROM users WHERE is_admin=1 AND telegram_id IS NOT NULL")
        ids |= {row[0] for row in cursor.fetchall()}
        conn.close()
    except Exception as e:
        logger.error(f"Не удалось получить админов из БД: {e}")
    return ids


def get_user_email(user_id_db) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT email FROM users WHERE id=?", (user_id_db,)).fetchone()
        conn.close()
        return (row[0] if row and row[0] else "unknown")
    except Exception:
        return "unknown"


def load_prouser() -> list:
    try:
        with open(PROUSER_PATH, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        return []
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        raise ValueError("ожидался список")
    except Exception as e:
        # Не затираем повреждённый файл — сохраняем копию
        backup = PROUSER_PATH + f".broken-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        try:
            os.replace(PROUSER_PATH, backup)
        except Exception:
            pass
        logger.error(f"prouser.json повреждён ({e}), копия: {backup}")
        return []


def save_prouser(records: list):
    tmp = PROUSER_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    os.replace(tmp, PROUSER_PATH)


def pay_key(payment_id) -> str:
    # callback_data в Telegram ограничен 64 байтами, поэтому используем короткий хеш
    return hashlib.sha1(str(payment_id).encode("utf-8")).hexdigest()[:16]


def format_payment_alert(rec: dict) -> str:
    return (
        f'Ошибка платежа! id_PAYMENT: "{esc(rec.get("id_PAYMENT", ""))}", '
        f'user_email: "{esc(rec.get("user_email", ""))}", '
        f'status: {esc(rec.get("status", ""))}'
    )


def payment_keyboard(rec: dict) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Успешно", callback_data=f"paydone:{pay_key(rec.get('id_PAYMENT', ''))}")
    ]])


async def report_failed_payment(charge_id: str, user_id_db):
    """Записывает неудавшуюся выдачу подписки в prouser.json и уведомляет админов."""
    email = get_user_email(user_id_db) if user_id_db else "unknown"
    rec = {"id_PAYMENT": charge_id, "user_email": email, "status": "anticipation"}

    try:
        records = load_prouser()
        if any(r.get("id_PAYMENT") == charge_id for r in records):
            logger.info(f"Платёж {charge_id} уже есть в prouser.json")
            return
        records.append(rec)
        save_prouser(records)
    except Exception as e:
        logger.error(f"Не удалось записать prouser.json: {e}")

    for admin_id in get_admin_ids():
        try:
            await bot.send_message(admin_id, "🚨 " + format_payment_alert(rec), reply_markup=payment_keyboard(rec))
        except Exception as e:
            logger.warning(f"Не удалось уведомить админа {admin_id}: {e}")


@dp.callback_query(F.data.startswith("paydone:"))
async def cb_payment_done(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("Нет прав.", show_alert=True)
        return

    key = callback.data.split(":", 1)[1]
    try:
        records = load_prouser()
        rec = next((r for r in records if pay_key(r.get("id_PAYMENT", "")) == key), None)
        if not rec:
            await callback.answer("Запись не найдена в prouser.json.", show_alert=True)
            return
        if rec.get("status") != "success":
            rec["status"] = "success"
            save_prouser(records)
    except Exception as e:
        logger.error(f"Ошибка обновления prouser.json: {e}")
        await callback.answer("Ошибка записи файла, см. логи.", show_alert=True)
        return

    try:
        await callback.message.edit_text(
            "✅ " + format_payment_alert(rec) + f"\n\nОтметил: {esc(callback.from_user.full_name)}"
        )
    except Exception:
        pass
    await callback.answer("Отмечено: success")


@dp.message(Command("pending"))
async def cmd_pending(message: Message):
    if not is_admin(message.from_user.id):
        return
    pending = [r for r in load_prouser() if r.get("status") != "success"]
    if not pending:
        await message.answer("✅ Необработанных платежей нет.")
        return
    for rec in pending:
        await message.answer("🚨 " + format_payment_alert(rec), reply_markup=payment_keyboard(rec))


@dp.message(F.successful_payment)
async def process_successful_payment(message: Message):
    payment_info = message.successful_payment
    payload = payment_info.invoice_payload
    stars_amount = payment_info.total_amount
    charge_id = payment_info.telegram_payment_charge_id

    try:
        user_id_db = int(payload.split("_")[-1])
    except Exception as e:
        logger.error(f"Не удалось распарсить payload: {e} (charge_id={charge_id})")
        await report_failed_payment(charge_id, None)
        await message.answer(
            f"⚠️ Платёж получен, но подписка не активировалась автоматически. "
            f"Администраторы уже уведомлены и выдадут её вручную.\nID платежа: <code>{esc(charge_id)}</code>"
        )
        return

    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        days = 30
        now_str = datetime.utcnow().isoformat(timespec="seconds")

        cursor.execute(
            "INSERT INTO payments (user_id, amount, currency, days, status, created, paid_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id_db, str(stars_amount), "XTR", days, "paid", now_str, now_str),
        )

        u = cursor.execute("SELECT subscription_until FROM users WHERE id=?", (user_id_db,)).fetchone()
        base = (
            datetime.fromisoformat(u[0])
            if u and u[0] and datetime.fromisoformat(u[0]) > datetime.utcnow()
            else datetime.utcnow()
        )
        new_sub_until = (base + timedelta(days=days)).isoformat()
        cursor.execute("UPDATE users SET subscription_until=? WHERE id=?", (new_sub_until, user_id_db))

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка платежа: {e} (charge_id={charge_id}, user_id_db={user_id_db})")
        if conn:
            conn.close()
        await report_failed_payment(charge_id, user_id_db)
        await message.answer(
            f"⚠️ Платёж получен, но подписка не активировалась автоматически. "
            f"Администраторы уже уведомлены и выдадут её вручную.\nID платежа: <code>{esc(charge_id)}</code>"
        )
        return

    # Подписка уже выдана — ошибка отправки сообщения не считается ошибкой платежа
    try:
        await message.answer(
            f"🎉 <b>Спасибо за покупку!</b>\n\n"
            f"Подписка PRO активирована на 30 дней.\n"
            f"• Списано звезд: {stars_amount} ⭐\n"
            f"• Активна до: <code>{new_sub_until[:10]}</code>\n\n"
            f"👉 {SITE_URL}"
        )
    except Exception as e:
        logger.error(f"Не удалось отправить подтверждение оплаты: {e}")


# --- Поддержка ---

@dp.message(Command("support"))
async def cmd_support(message: Message):
    await message.answer(
        "САППОРТ НЕ ДОСТУПЕН ЗДЕСЬ! Продолжите в одном из двух:\n"
        "t.me/rahmatullohrobot — t.me/odilxojarobot"
    )


# --- Смена пароля и отмена подписки ---

@dp.message(Command("change_password"))
async def cmd_change_password(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")
    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return
    await message.answer("🔑 Введите ваш <b>текущий пароль</b>:")
    await state.set_state(ChangePasswordStates.waiting_for_old_password)


@dp.message(ChangePasswordStates.waiting_for_old_password, F.text)
async def process_old_password(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    data = await state.get_data()
    user_id_db = data.get("user_id_db")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id=?", (user_id_db,))
        row = cursor.fetchone()
        conn.close()
        if not row or not (check_password_hash(row[0], message.text) or message.text == row[0]):
            await message.answer("❌ Неверный текущий пароль. Попробуйте снова: /change_password")
            await state.set_state(None)
            return
        await message.answer("✅ Подтверждено.\n\n🔒 Введите <b>новый пароль</b> (минимум 6 символов):")
        await state.set_state(ChangePasswordStates.waiting_for_new_password)
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        await message.answer("⚠️ Произошла ошибка. Попробуйте позже.")
        await state.set_state(None)


@dp.message(ChangePasswordStates.waiting_for_new_password, F.text)
async def process_new_password(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    if len(message.text) < 6:
        await message.answer("❌ Пароль слишком короткий. Минимум 6 символов:")
        return
    await state.update_data(new_password=message.text)
    await message.answer("🔒 Повторите <b>новый пароль</b>:")
    await state.set_state(ChangePasswordStates.waiting_for_confirm_password)


@dp.message(ChangePasswordStates.waiting_for_confirm_password, F.text)
async def process_confirm_password(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    data = await state.get_data()
    if data.get("new_password") != message.text:
        await message.answer("❌ Пароли не совпадают. Начните заново: /change_password")
        await state.set_state(None)
        return
    try:
        new_hash = generate_password_hash(message.text)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, data.get("user_id_db")))
        conn.commit()
        conn.close()
        await message.answer("✅ <b>Пароль успешно изменен!</b>")
        await state.set_state(None)
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        await message.answer("⚠️ Произошла ошибка. Попробуйте позже.")
        await state.set_state(None)


@dp.message(Command("stop_subscription"))
async def cmd_stop_subscription(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")
    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now_str = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
        cursor.execute("UPDATE users SET subscription_until=? WHERE id=?", (now_str, user_id_db))
        conn.commit()
        conn.close()
        await message.answer("🛑 <b>Подписка отменена.</b>")
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        await message.answer("⚠️ Произошла ошибка. Попробуйте позже.")


# ==========================================
# --- КОМАНДЫ ТЕХНИЧЕСКОЙ ПОДДЕРЖКИ (ADMIN) ---
# ==========================================

@dp.message(Command("admin"))
async def cmd_admin_panel(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ У вас нет прав администратора.")
        return
    await message.answer(
        "🛠 <b>Панель технической поддержки (Admin):</b>\n\n"
        "• <code>/permban [email] [причина]</code> — вечный бан\n"
        "• <code>/ban [email] [срок_в_днях] [причина]</code> — временный бан\n"
        "• <code>/givepro [email] [срок_в_днях] [за_что]</code> — выдать PRO тариф\n"
        "• <code>/cancelpro [email] [причина]</code> — отменить PRO тариф\n"
        "• <code>/resetpassword [email]</code> — сбросить пароль\n"
        "• <code>/sms [текст]</code> — рассылка всем юзерам\n"
        "• <code>/smsadmin [текст]</code> — рассылка админам\n"
        "• <code>/setadmin [email]</code> — сделать админом\n"
        "• <code>/rename [email] [новый_ник]</code> — поменять ник\n"
        "• <code>/pending</code> — необработанные платежи (prouser.json)"
    )


@dp.message(Command("permban"))
async def cmd_permban(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: <code>/permban [email] [причина]</code>")
        return
    email, reason = args[1], args[2]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, telegram_id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    uid, tg_id = u[0], u[1]
    cursor.execute("UPDATE users SET status='perm_banned', ban_reason=? WHERE id=?", (reason, uid))
    conn.commit()
    conn.close()

    if tg_id:
        try:
            await bot.send_message(tg_id, f"🚫 <b>Ваш аккаунт заблокирован навсегда.</b>\nПричина: {esc(reason)}")
        except Exception: pass
    await message.answer(f"✅ Пользователь {esc(email)} заблокирован навсегда.")


@dp.message(Command("ban"))
async def cmd_ban(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=3)
    if len(args) < 4:
        await message.answer("⚠️ Использование: <code>/ban [email] [срок_в_днях] [причина]</code>")
        return
    email, days_str, reason = args[1], args[2], args[3]
    try:
        days = int(days_str)
    except ValueError:
        await message.answer("❌ Срок должен быть числом дней.")
        return

    banned_until = (datetime.utcnow() + timedelta(days=days)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, telegram_id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    uid, tg_id = u[0], u[1]
    cursor.execute("UPDATE users SET status='banned', banned_until=?, ban_reason=? WHERE id=?", (banned_until, reason, uid))
    conn.commit()
    conn.close()

    if tg_id:
        try:
            await bot.send_message(tg_id, f"🚫 <b>Ваш аккаунт заблокирован.</b>\nСрок до: {banned_until[:16]}\nПричина: {esc(reason)}")
        except Exception: pass
    await message.answer(f"✅ Пользователь {esc(email)} заблокирован на {days} дней.")


@dp.message(Command("givepro"))
async def cmd_givepro(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=3)
    if len(args) < 4:
        await message.answer("⚠️ Использование: <code>/givepro [email] [срок_в_днях] [за_что]</code>")
        return
    email, days_str, reason = args[1], args[2], args[3]
    try:
        days = int(days_str)
    except ValueError:
        await message.answer("❌ Срок должен быть числом дней.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, subscription_until, telegram_id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    uid, sub_until_str, tg_id = u[0], u[1], u[2]
    base = (
        datetime.fromisoformat(sub_until_str)
        if sub_until_str and datetime.fromisoformat(sub_until_str) > datetime.utcnow()
        else datetime.utcnow()
    )
    new_sub_until = (base + timedelta(days=days)).isoformat()
    cursor.execute("UPDATE users SET subscription_until=? WHERE id=?", (new_sub_until, uid))
    conn.commit()
    conn.close()

    sub_date_formatted = new_sub_until[:10]
    if tg_id:
        try:
            await bot.send_message(tg_id, f"🎉 <b>Вам выдали тариф!</b>\nСрок истечения: {sub_date_formatted}\nПричина: {esc(reason)}")
        except Exception: pass
    await message.answer(f"✅ Пользователю {esc(email)} выдан PRO тариф до {sub_date_formatted}.")


@dp.message(Command("cancelpro"))
async def cmd_cancelpro(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: <code>/cancelpro [email] [причина]</code>")
        return
    email, reason = args[1], args[2]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, telegram_id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    uid, tg_id = u[0], u[1]
    now_str = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
    cursor.execute("UPDATE users SET subscription_until=? WHERE id=?", (now_str, uid))
    conn.commit()
    conn.close()

    if tg_id:
        try:
            await bot.send_message(tg_id, f"🛑 <b>Ваш PRO тариф был отменен.</b>\nПричина: {esc(reason)}")
        except Exception: pass
    await message.answer(f"✅ PRO тариф пользователя {esc(email)} отменен.")


@dp.message(Command("resetpassword"))
async def cmd_resetpassword(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: <code>/resetpassword [email]</code>")
        return
    email = args[1]

    new_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    new_hash = generate_password_hash(new_pass)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, telegram_id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    uid, tg_id = u[0], u[1]
    cursor.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, uid))
    conn.commit()
    conn.close()

    if tg_id:
        try:
            await bot.send_message(tg_id, f"🔑 <b>Ваш пароль был сброшен.</b>\nНовый временный пароль: <code>{new_pass}</code>")
        except Exception: pass
    await message.answer(f"✅ Пароль для {esc(email)} сброшен.\nНовый пароль: <code>{new_pass}</code>")


async def _send_one(tg_id: int, text: str, sem: asyncio.Semaphore) -> str:
    """Отправка одного сообщения. Возвращает 'ok' / 'blocked' / 'failed'."""
    async with sem:
        for _ in range(3):
            try:
                await bot.send_message(tg_id, text)
                return "ok"
            except TelegramRetryAfter as e:
                # Telegram просит притормозить — ждём ровно сколько надо и пробуем снова
                await asyncio.sleep(e.retry_after + 1)
            except TelegramForbiddenError:
                return "blocked"  # юзер заблокировал бота
            except Exception as e:
                logger.warning(f"Не удалось отправить {tg_id}: {e}")
                return "failed"
        return "failed"


async def _run_broadcast(admin_chat_id: int, tg_ids: list, text: str):
    sem = asyncio.Semaphore(20)  # до 20 отправок одновременно (лимит Telegram ~30/сек)
    results = await asyncio.gather(*(_send_one(i, text, sem) for i in tg_ids))
    ok = results.count("ok")
    blocked = results.count("blocked")
    failed = results.count("failed")
    await bot.send_message(
        admin_chat_id,
        f"✅ Рассылка готова.\n"
        f"Доставлено: {ok}\n"
        f"Заблокировали бота: {blocked}\n"
        f"Ошибок: {failed}",
    )


_broadcast_tasks: set = set()


@dp.message(Command("sms"))
async def cmd_sms(message: Message):
    if not is_admin(message.from_user.id): return
    # html_text сохраняет переносы строк и форматирование (жирный, курсив, ссылки)
    parts = (message.html_text or "").split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("⚠️ Использование: <code>/sms [текст]</code>")
        return
    text = f"📢 {parts[1]}"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT telegram_id FROM users WHERE telegram_id IS NOT NULL "
        "UNION SELECT telegram_id FROM bot_chats"
    )
    tg_ids = {row[0] for row in cursor.fetchall()}
    conn.close()
    tg_ids.add(message.from_user.id)  # чтобы админ тоже увидел сообщение в чате с ботом
    tg_ids = list(tg_ids)

    await message.answer(f"📤 Отправляю {len(tg_ids)} пользователям, скоро напишу итог.")
    # Запускаем в фоне, чтобы бот не «зависал» на время рассылки
    task = asyncio.create_task(_run_broadcast(message.chat.id, tg_ids, text))
    _broadcast_tasks.add(task)
    task.add_done_callback(_broadcast_tasks.discard)


@dp.message(Command("smsadmin"))
async def cmd_smsadmin(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: <code>/smsadmin [текст]</code>")
        return
    text = args[1]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT telegram_id FROM users WHERE is_admin=1 AND telegram_id IS NOT NULL")
    admin_ids = {row[0] for row in cursor.fetchall()} | set(ADMIN_IDS)
    conn.close()

    success = 0
    for tg_id in admin_ids:
        try:
            await bot.send_message(tg_id, f"🛡 <b>Для админов:</b>\n\n{esc(text)}")
            success += 1
        except Exception:
            pass
    await message.answer(f"✅ Отправлено админам ({success}).")


@dp.message(Command("setadmin"))
async def cmd_setadmin(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: <code>/setadmin [email]</code>")
        return
    email = args[1]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    cursor.execute("UPDATE users SET is_admin=1 WHERE id=?", (u[0],))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Пользователь {esc(email)} теперь администратор.")


@dp.message(Command("rename"))
async def cmd_rename(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: <code>/rename [email] [новый_ник]</code>")
        return
    email, new_name = args[1], args[2]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (email,))
    u = cursor.fetchone()
    if not u:
        conn.close()
        await message.answer("❌ Пользователь с таким email не найден.")
        return
    cursor.execute("UPDATE users SET username=? WHERE id=?", (new_name, u[0]))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Ник пользователя {esc(email)} изменен на <code>{esc(new_name)}</code>.")


# --- Запуск ---

async def main():
    if os.path.exists(DB_PATH):
        logger.info(f"База данных найдена: {DB_PATH}")
        init_db_columns()
    else:
        logger.error(f"База данных НЕ НАЙДЕНА: {DB_PATH} — укажите правильный путь в .env (DB_PATH=...)")
        return

    # Если у бота ранее был включён вебхук, polling не будет получать сообщения
    await bot.delete_webhook(drop_pending_updates=False)

    logger.info("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Бот остановлен.")
