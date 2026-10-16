import asyncio
import sqlite3
import os
import logging
import random
import string
from dotenv import load_dotenv
from datetime import datetime, timedelta
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import Message, LabeledPrice, PreCheckoutQuery, ReplyKeyboardRemove, FSInputFile
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
SUBSCRIPTION_PRICE = os.getenv("SUBSCRIPTION_PRICE")
SITE_URL = os.getenv("SITE_URL", "https://retrudio.com")

# Список ID администраторов
ADMIN_IDS = [5025390367, 8221414112]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SCHEMS_DIR = os.path.join(BASE_DIR, "Schems")

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "app.db")

# Защита от брутфорса: {telegram_id: {"attempts": int, "blocked_until": datetime}}
_login_attempts: dict = {}
MAX_ATTEMPTS = 5          
BLOCK_DURATION_MIN = 15   
# -----------------

bot = Bot(token=BOT_TOKEN, is_test=False)
dp = Dispatcher()


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
            
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка инициализации колонок БД: {e}")

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
    caption_text = (
        "📜 **Ознакомьтесь с правилами сервиса.**\n\n"
        "Если вы согласны с условиями использования, "
        "войдите в аккаунт командой: /login\n\n"
        "📋 Список команд: /help"
    )
    if os.path.exists(docs_path):
        document = FSInputFile(docs_path)
        await message.answer_document(document=document, caption=caption_text)
    else:
        await message.answer("⚠️ Файл с правилами не найден.\n\n" + caption_text)


@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "📋 **Список команд:**\n\n"
        "/start — начало работы\n"
        "/login — войти в аккаунт\n"
        "/buy — купить подписку (30 дней)\n"
        "/status — проверить статус подписки\n"
        "/change_password — сменить пароль\n"
        "/stop_subscription — отменить подписку\n"
        "/help — это сообщение"
    )

@dp.message(Command("support"))
async def cmd_support(message: Message):
    await message.answer(
        "САППОРТ НЕ ДОСТУПЕН ЗДЕСЬ! Продолжите в одном из двух:\n"
        "t.me/rahmatullohrobot — t.me/odilxojarobot"
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
                status_text = f"✅ **Активна** до `{sub_until[:10]}` (осталось {days_left} дн.)"
            else:
                status_text = "❌ **Истекла**"
        else:
            status_text = "❌ **Нет подписки**"

        await message.answer(
            f"👤 **Аккаунт:**\n"
            f"• Имя: `{username or '—'}`\n"
            f"• Email: `{email or '—'}`\n\n"
            f"⭐ **Подписка:** {status_text}\n\n"
            f"Купить/продлить: /buy"
        )
    except Exception as e:
        logger.error(f"Ошибка /status: {e}")
        await message.answer(f"⚠️ Ошибка: {e}")


# --- Авторизация и проверка статусов банов ---

@dp.message(Command("login"))
async def cmd_login(message: Message, state: FSMContext):
    tg_id = message.from_user.id
    blocked, mins = is_blocked_brute(tg_id)
    if blocked:
        await message.answer(f"🚫 **Слишком много неудачных попыток.**\nПовторите через {mins} мин.")
        return

    await message.answer(
        "🔐 **Авторизация**\n\nВведите ваш **логин** или email от сайта:",
        reply_markup=ReplyKeyboardRemove(),
    )
    await state.set_state(AuthStates.waiting_for_login)


@dp.message(AuthStates.waiting_for_login)
async def process_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text)
    await message.answer("🔑 Введите ваш **пароль**:")
    await state.set_state(AuthStates.waiting_for_password)


@dp.message(AuthStates.waiting_for_password)
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
        await message.answer(f"🚫 **Слишком много неудачных попыток.**\nПовторите через {mins} мин.")
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
                await message.answer(f"🚫 **Ваш аккаунт заблокирован навсегда.**\nПричина: {ban_reason or 'Нарушение правил'}")
                return
            elif status == 'banned' and banned_until:
                banned_dt = datetime.fromisoformat(banned_until)
                if banned_dt > datetime.utcnow():
                    conn.close()
                    await state.clear()
                    await message.answer(f"🚫 **Ваш аккаунт заблокирован.**\nСрок: до {banned_until[:16]}\nПричина: {ban_reason or 'Нарушение правил'}")
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
                    f"✅ **Вход выполнен!**\n"
                    f"Привет, {display_name}!\n\n"
                    f"• Статус подписки: /status\n"
                    f"• Купить подписку: /buy\n"
                    f"• Сменить пароль: /change\\_password"
                )
            else:
                conn.close()
                remaining = record_failed_attempt(tg_id)
                if remaining == 0:
                    await state.clear()
                    await message.answer(f"🚫 **Превышен лимит попыток.**\nАккаунт заблокирован на {BLOCK_DURATION_MIN} мин.")
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
        await message.answer(f"⚠️ Ошибка базы данных: {e}")
        await state.clear()


# --- Оплата и прочие команды ---

@dp.message(Command("buy"))
async def cmd_buy(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")

    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return

    prices = [LabeledPrice(label="Подписка (30 дней)", amount=int(SUBSCRIPTION_PRICE))]
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


@dp.message(F.successful_payment)
async def process_successful_payment(message: Message):
    payment_info = message.successful_payment
    payload = payment_info.invoice_payload
    stars_amount = payment_info.total_amount

    try:
        user_id_db = int(payload.split("_")[-1])
    except Exception as e:
        logger.error(f"Не удалось распарсить payload: {e}")
        return

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

        await message.answer(
            f"🎉 **Спасибо за покупку!**\n\n"
            f"Подписка PRO активирована на 30 дней.\n"
            f"• Списано звезд: {stars_amount} ⭐\n"
            f"• Активна до: `{new_sub_until[:10]}`\n\n"
            f"👉 {SITE_URL}"
        )
    except Exception as e:
        logger.error(f"Ошибка платежа: {e}")


# --- Смена пароля и отмена подписки ---

@dp.message(Command("change_password"))
async def cmd_change_password(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id_db = data.get("user_id_db")
    if not user_id_db:
        await message.answer("⚠️ Сначала войдите в аккаунт: /login")
        return
    await message.answer("🔑 Введите ваш **текущий пароль**:")
    await state.set_state(ChangePasswordStates.waiting_for_old_password)


@dp.message(ChangePasswordStates.waiting_for_old_password)
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
            await message.answer("❌ Неверный текущий пароль. Попробуйте снова: /change\\_password")
            await state.set_state(None)
            return
        await message.answer("✅ Подтверждено.\n\n🔒 Введите **новый пароль** (минимум 6 символов):")
        await state.set_state(ChangePasswordStates.waiting_for_new_password)
    except Exception as e:
        await message.answer(f"⚠️ Ошибка: {e}")
        await state.set_state(None)


@dp.message(ChangePasswordStates.waiting_for_new_password)
async def process_new_password(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    if len(message.text) < 6:
        await message.answer("❌ Пароль слишком короткий. Минимум 6 символов:")
        return
    await state.update_data(new_password=message.text)
    await message.answer("🔒 Повторите **новый пароль**:")
    await state.set_state(ChangePasswordStates.waiting_for_confirm_password)


@dp.message(ChangePasswordStates.waiting_for_confirm_password)
async def process_confirm_password(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    data = await state.get_data()
    if data.get("new_password") != message.text:
        await message.answer("❌ Пароли не совпадают. Начните заново: /change\\_password")
        await state.set_state(None)
        return
    try:
        new_hash = generate_password_hash(message.text)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, data.get("user_id_db")))
        conn.commit()
        conn.close()
        await message.answer("✅ **Пароль успешно изменен!**")
        await state.set_state(None)
    except Exception as e:
        await message.answer(f"⚠️ Ошибка: {e}")
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
        await message.answer("🛑 **Подписка отменена.**")
    except Exception as e:
        await message.answer(f"⚠️ Ошибка: {e}")


# ==========================================
# --- КОМАНДЫ ТЕХНИЧЕСКОЙ ПОДДЕРЖКИ (ADMIN) ---
# ==========================================

@dp.message(Command("admin"))
async def cmd_admin_panel(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ У вас нет прав администратора.")
        return
    await message.answer(
        "🛠 **Панель технической поддержки (Admin):**\n\n"
        "• `/permban [email] [причина]` — вечный бан\n"
        "• `/ban [email] [срок_в_днях] [причина]` — временный бан\n"
        "• `/givepro [email] [срок_в_днях] [за_что]` — выдать PRO тариф\n"
        "• `/cancelpro [email] [причина]` — отменить PRO тариф\n"
        "• `/resetpassword [email]` — сбросить пароль\n"
        "• `/sms [текст]` — рассылка всем юзерам\n"
        "• `/smsadmin [текст]` — рассылка админам\n"
        "• `/setadmin [email]` — сделать админом\n"
        "• `/rename [email] [новый_ник]` — поменять ник"
    )


@dp.message(Command("permban"))
async def cmd_permban(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: `/permban [email] [причина]`")
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
            await bot.send_message(tg_id, f"🚫 **Ваш аккаунт заблокирован навсегда.**\nПричина: {reason}")
        except: pass
    await message.answer(f"✅ Пользователь {email} заблокирован навсегда.")


@dp.message(Command("ban"))
async def cmd_ban(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=3)
    if len(args) < 4:
        await message.answer("⚠️ Использование: `/ban [email] [срок_в_днях] [причина]`")
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
            await bot.send_message(tg_id, f"🚫 **Ваш аккаунт заблокирован.**\nСрок до: {banned_until[:16]}\nПричина: {reason}")
        except: pass
    await message.answer(f"✅ Пользователь {email} заблокирован на {days} дней.")


@dp.message(Command("givepro"))
async def cmd_givepro(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=3)
    if len(args) < 4:
        await message.answer("⚠️ Использование: `/givepro [email] [срок_в_днях] [за_что]`")
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
            await bot.send_message(tg_id, f"🎉 **Вам выдали тариф!**\nСрок истечения: {sub_date_formatted}\nПричина: {reason}")
        except: pass
    await message.answer(f"✅ Пользователю {email} выдан PRO тариф до {sub_date_formatted}.")


@dp.message(Command("cancelpro"))
async def cmd_cancelpro(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: `/cancelpro [email] [причина]`")
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
            await bot.send_message(tg_id, f"🛑 **Ваш PRO тариф был отменен.**\nПричина: {reason}")
        except: pass
    await message.answer(f"✅ PRO тариф пользователя {email} отменен.")


@dp.message(Command("resetpassword"))
async def cmd_resetpassword(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: `/resetpassword [email]`")
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
            await bot.send_message(tg_id, f"🔑 **Ваш пароль был сброшен.**\nНовый временный пароль: `{new_pass}`")
        except: pass
    await message.answer(f"✅ Пароль для {email} сброшен.\nНовый пароль: `{new_pass}`")


@dp.message(Command("sms"))
async def cmd_sms(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: `/sms [текст]`")
        return
    text = args[1]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT telegram_id FROM users WHERE telegram_id IS NOT NULL")
    users = cursor.fetchall()
    conn.close()

    success, failed = 0, 0
    for row in users:
        tg_id = row[0]
        try:
            await bot.send_message(tg_id, f"📢 **Рассылка от техподдержки:**\n\n{text}")
            success += 1
            await asyncio.sleep(0.05)
        except:
            failed += 1
    await message.answer(f"✅ Рассылка завершена.\nДоставлено: {success}, ошибок: {failed}")


@dp.message(Command("smsadmin"))
async def cmd_smsadmin(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: `/smsadmin [текст]`")
        return
    text = args[1]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT telegram_id FROM users WHERE is_admin=1 OR telegram_id IN (%s)" % ','.join(map(str, ADMIN_IDS)))
    admins = cursor.fetchall()
    conn.close()

    success = 0
    for row in admins:
        tg_id = row[0]
        if tg_id:
            try:
                await bot.send_message(tg_id, f"🛡 **Для админов:**\n\n{text}")
                success += 1
            except: pass
    await message.answer(f"✅ Отправлено админам ({success}).")


@dp.message(Command("setadmin"))
async def cmd_setadmin(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("⚠️ Использование: `/setadmin [email]`")
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
    await message.answer(f"✅ Пользователь {email} теперь администратор.")


@dp.message(Command("rename"))
async def cmd_rename(message: Message):
    if not is_admin(message.from_user.id): return
    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("⚠️ Использование: `/rename [email] [новый_ник]`")
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
    await message.answer(f"✅ Ник пользователя {email} изменен на `{new_name}`.")


# --- Запуск ---

async def main():
    init_db_columns()
    if os.path.exists(DB_PATH):
        logger.info(f"База данных найдена: {DB_PATH}")
    else:
        logger.error(f"База данных НЕ НАЙДЕНА: {DB_PATH}")

    logger.info("Бот запущен...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Бот остановлен.")s
