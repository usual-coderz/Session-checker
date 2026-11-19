#!/usr/bin/env python3
"""Restriction checker bot (owner-only). Mongo backed.
txt file bhejo -> rejected / clean / dead / errors alag files + counts."""
import asyncio, io, os, re, time, logging
from contextlib import suppress

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from telethon import TelegramClient, functions, events
from telethon.sessions import StringSession
from telethon.crypto import AuthKey
from telethon.errors import (
    RPCError, AuthKeyUnregisteredError, AuthKeyDuplicatedError, SessionRevokedError,
    UserDeactivatedBanError, UserDeactivatedError, FloodWaitError,
)

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("chkbot")

API_ID = int(os.getenv("API_ID", "0"))
API_HASH = os.getenv("API_HASH", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
OWNER_IDS = {int(x) for x in os.getenv("OWNER_IDS", "").replace(" ", "").split(",") if x}
CONCURRENCY = int(os.getenv("CONCURRENCY", "10"))
MAX_MB = int(os.getenv("MAX_MB", "10"))
MONGO_URI = os.getenv("MONGO_URI", "")
MONGO_DB = os.getenv("MONGO_DB", "session_checker")

DC_IPS = {1: "149.154.175.53", 2: "149.154.167.51", 3: "149.154.175.100",
          4: "149.154.167.91", 5: "91.108.56.130"}
HEX_RE = re.compile(r"^[0-9a-fA-F]{512}:\d{1,2}$")
PHONE_RE = re.compile(r"^\+?\d{6,15}$")

REJECT_MARKERS = ("contact address restriction", "phone_number_rejected", "is rejected due to")
DEAD_MARKERS = ("auth_key_unregistered", "auth_key_duplicated", "session_revoked",
                "user_deactivated", "auth_key_invalid", "session_expired")

SEM = asyncio.Semaphore(CONCURRENCY)
BUSY = {"running": False}
CANCEL = asyncio.Event()
COLL = None


# ---------------- mongo ----------------
async def db_init():
    global COLL
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=15000)
    await client.admin.command("ping")
    COLL = client[MONGO_DB]["sessions"]
    await COLL.create_index("session", unique=True)
    await COLL.create_index("status")
    log.info("mongo connected")


async def save(sess, phone, status, note):
    with suppress(Exception):
        await COLL.update_one(
            {"session": sess},
            {"$set": {"phone": phone, "status": status, "note": note, "ts": int(time.time())}},
            upsert=True,
        )


async def counts():
    d = {}
    async for row in COLL.aggregate([{"$group": {"_id": "$status", "c": {"$sum": 1}}}]):
        d[row["_id"]] = row["c"]
    return d


# ---------------- sessions ----------------
def make_client(sess: str) -> TelegramClient:
    return TelegramClient(
        StringSession(sess), API_ID, API_HASH,
        device_model="Samsung SM-A546E", system_version="SDK 34",
        app_version="10.14.5 (5292)", lang_code="en", system_lang_code="en",
        connection_retries=2, retry_delay=1, timeout=25, flood_sleep_threshold=0,
    )


def hex_to_string_session(raw: str) -> str:
    key_hex, dc = raw.split(":")
    dc = int(dc)
    if dc not in DC_IPS:
        raise ValueError("bad dc")
    mem = StringSession()
    mem.set_dc(dc, DC_IPS[dc], 443)
    mem.auth_key = AuthKey(bytes.fromhex(key_hex))
    out = mem.save()
    if not out:
        raise ValueError("convert fail")
    return out


def normalize(tok: str):
    tok = tok.strip()
    if HEX_RE.match(tok):
        try:
            return hex_to_string_session(tok)
        except Exception:
            return None
    if len(tok) > 100 and re.fullmatch(r"[A-Za-z0-9_\-=]+", tok):
        return tok
    return None


def parse(text: str):
    out, bad, seen = [], 0, set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        phone = sess = None
        for part in re.split(r"[\s|,;]+", line):
            if not part:
                continue
            s = normalize(part)
            if s:
                sess = s
            elif PHONE_RE.match(part):
                phone = part
        if not sess:
            bad += 1
            continue
        if sess in seen:
            continue
        seen.add(sess)
        out.append((phone, sess))
    return out, bad


def etext(e: Exception) -> str:
    return (getattr(e, "message", "") or str(e) or "").strip()


def line_of(phone, sess):
    return f"{phone} {sess}" if phone else sess


async def probe(phone, sess):
    for attempt in range(2):
        cli = make_client(sess)
        try:
            await cli.connect()
            await cli(functions.updates.GetStateRequest())
            me = await cli.get_me()
            if not me:
                return "dead", phone, "unauthorized"
            with suppress(Exception):
                await cli(functions.account.UpdateStatusRequest(offline=False))
            return "clean", phone, None
        except FloodWaitError as e:
            if attempt == 0 and not CANCEL.is_set():
                await asyncio.sleep(min(e.seconds + 3, 180))
                continue
            return "error", phone, f"flood {e.seconds}s"
        except (AuthKeyUnregisteredError, AuthKeyDuplicatedError,
                SessionRevokedError, UserDeactivatedBanError, UserDeactivatedError) as e:
            return "dead", phone, etext(e)
        except RPCError as e:
            txt = etext(e)
            low = txt.lower()
            if any(m in low for m in REJECT_MARKERS) or "rejected" in low:
                m = re.search(r"\+(\d{6,15})", txt)
                return "rejected", (m.group(0) if m else phone), txt
            if any(m in low for m in DEAD_MARKERS):
                return "dead", phone, txt
            return "error", phone, txt
        except Exception as e:
            return "error", phone, f"{type(e).__name__}: {e}"
        finally:
            with suppress(Exception):
                await cli.disconnect()
    return "error", phone, "retry fail"


async def run_job(event, items, bad):
    total = len(items)
    buckets = {"rejected": [], "clean": [], "dead": [], "error": []}
    status_msg = await event.reply(f"{total} sessions mila. Check shuru… (0/{total})")
    last_edit, done = 0.0, 0

    async def one(phone, sess):
        nonlocal done, last_edit
        async with SEM:
            if CANCEL.is_set():
                return
            res, ph, note = await probe(phone, sess)
            buckets[res].append((ph, sess, note))
            await save(sess, ph, res, note)
            done += 1
            now = time.time()
            if now - last_edit > 2.5 or done == total:
                last_edit = now
                with suppress(Exception):
                    await status_msg.edit(f"Checking… {done}/{total}")

    try:
        await asyncio.gather(*(one(p, s) for p, s in items))
    finally:
        BUSY["running"] = False

    summary = (f"**Result**\n\n"
               f"total: {total}\nrejected: {len(buckets['rejected'])}\n"
               f"clean: {len(buckets['clean'])}\ndead: {len(buckets['dead'])}\n"
               f"error: {len(buckets['error'])}\ninvalid: {bad}"
               + ("\n\n(stop kiya gaya — partial)" if CANCEL.is_set() else ""))
    with suppress(Exception):
        await status_msg.edit(summary)

    for key, fname in (("rejected", "rejected.txt"), ("clean", "clean.txt"),
                       ("dead", "dead.txt"), ("error", "errors.txt")):
        rows = buckets[key]
        if not rows:
            continue
        buf = io.BytesIO("\n".join(line_of(p, s) for p, s, _ in rows).encode())
        with suppress(Exception):
            await event.reply(f"{key}: {len(rows)}", file=(fname, buf))
    CANCEL.clear()


def owner_only(fn):
    async def wrapper(event):
        if event.sender_id not in OWNER_IDS:
            return
        await fn(event)
    return wrapper


async def main():
    await db_init()
    bot = TelegramClient(StringSession(), API_ID, API_HASH)

    @bot.on(events.NewMessage(pattern=r"^/(start|help)"))
    @owner_only
    async def cmd_help(e):
        await e.reply(
            "**Restriction checker**\n\n"
            "txt file bhejo — har line me session (phone optional).\n"
            "Output: rejected / clean / dead / errors alag files + counts.\n\n"
            "/stats — ab tak ka hisaab\n/rejected /clean /dead /errors — stored list file\n"
            "/stop — chal raha check roko\n/reset — DB clear"
        )

    @bot.on(events.NewMessage(func=lambda e: e.document is not None))
    @owner_only
    async def on_file(e):
        if BUSY["running"]:
            await e.reply("Ek check pehle se chal raha hai. `/stop` se roko.")
            return
        doc = e.document
        if doc.size > MAX_MB * 1024 * 1024:
            await e.reply(f"File {MAX_MB} MB se badi hai.")
            return
        raw = await e.download_media(bytes)
        items, bad = parse(raw.decode("utf-8", "ignore"))
        if not items:
            await e.reply("Koi valid session nahi mila. Format: `session` ya `phone session` per line.")
            return
        BUSY["running"] = True
        asyncio.create_task(run_job(e, items, bad))

    @bot.on(events.NewMessage(pattern=r"^/stop$"))
    @owner_only
    async def cmd_stop(e):
        CANCEL.set()
        await e.reply("Stop signal bheja, current requests ke baad rukega.")

    @bot.on(events.NewMessage(pattern=r"^/stats$"))
    @owner_only
    async def cmd_stats(e):
        d = await counts()
        await e.reply(f"total: {sum(d.values())}\nrejected: {d.get('rejected',0)} | "
                      f"clean: {d.get('clean',0)} | dead: {d.get('dead',0)} | "
                      f"error: {d.get('error',0)}")

    @bot.on(events.NewMessage(pattern=r"^/(rejected|clean|dead|errors)$"))
    @owner_only
    async def cmd_list(e):
        key = e.raw_text.strip().lstrip("/").replace("errors", "error")
        rows = [r async for r in COLL.find({"status": key})]
        if not rows:
            await e.reply("Khali.")
            return
        buf = io.BytesIO("\n".join(line_of(r.get("phone"), r["session"]) for r in rows).encode())
        await e.reply(f"{len(rows)}", file=(f"{key}.txt", buf))

    @bot.on(events.NewMessage(pattern=r"^/reset$"))
    @owner_only
    async def cmd_reset(e):
        await COLL.delete_many({})
        await e.reply("DB clear.")

    await bot.start(bot_token=BOT_TOKEN)
    me = await bot.get_me()
    log.info("checker bot @%s up", me.username)
    await bot.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())