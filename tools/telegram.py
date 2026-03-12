import os
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"

MAX_MSG_LEN = 4096  # Telegram message limit


def send_telegram(message: str, chat_id: str = "", parse_mode: str = "Markdown",
                  disable_preview: bool = True) -> str:
    """Send a message or report to the user's Telegram account via the bot.

    Args:
        message: Text to send. Supports Markdown formatting. Long messages are auto-split.
        chat_id: Override chat ID. Leave empty to use the default from .env.
        parse_mode: 'Markdown', 'HTML', or '' for plain text.
        disable_preview: Disable link previews in the message.
    """
    if not BOT_TOKEN:
        return "ERROR: TELEGRAM_BOT_TOKEN not set in .env file."

    target_chat = chat_id or TELEGRAM_CHAT_ID
    if not target_chat:
        # Try to auto-discover chat ID from recent messages to the bot
        target_chat = _discover_chat_id()
        if not target_chat:
            return ("ERROR: No TELEGRAM_CHAT_ID set and no recent messages found.\n"
                    "Please send any message to @AI_Recon_Agent_bot on Telegram first, "
                    "then try again. Or set TELEGRAM_CHAT_ID in .env.")

    # Split long messages
    chunks = _split_message(message)
    sent = 0
    errors = []

    for chunk in chunks:
        try:
            payload = {
                "chat_id": target_chat,
                "text": chunk,
                "disable_web_page_preview": disable_preview,
            }
            if parse_mode:
                payload["parse_mode"] = parse_mode

            resp = requests.post(f"{API_BASE}/sendMessage", json=payload, timeout=15)
            data = resp.json()

            if data.get("ok"):
                sent += 1
            else:
                # If Markdown fails, retry as plain text
                if parse_mode and "can't parse" in str(data.get("description", "")).lower():
                    payload.pop("parse_mode", None)
                    resp2 = requests.post(f"{API_BASE}/sendMessage", json=payload, timeout=15)
                    data2 = resp2.json()
                    if data2.get("ok"):
                        sent += 1
                    else:
                        errors.append(data2.get("description", "Unknown error"))
                else:
                    errors.append(data.get("description", "Unknown error"))
        except Exception as e:
            errors.append(str(e))

    if errors:
        return f"Sent {sent}/{len(chunks)} message(s) to Telegram. Errors: {'; '.join(errors)}"
    return f"✓ Report sent to Telegram ({sent} message{'s' if sent > 1 else ''}, {len(message)} chars)"


def send_telegram_file(file_path: str, caption: str = "", chat_id: str = "") -> str:
    """Send a file (report, image, etc.) to Telegram.

    Args:
        file_path: Path to the file to send.
        caption: Optional caption for the file.
        chat_id: Override chat ID.
    """
    if not BOT_TOKEN:
        return "ERROR: TELEGRAM_BOT_TOKEN not set in .env file."

    target_chat = chat_id or TELEGRAM_CHAT_ID
    if not target_chat:
        target_chat = _discover_chat_id()
        if not target_chat:
            return "ERROR: No TELEGRAM_CHAT_ID set. Send a message to the bot first."

    path = Path(file_path)
    if not path.exists():
        return f"ERROR: File not found: {file_path}"

    try:
        ext = path.suffix.lower()
        # Choose the right endpoint based on file type
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
            endpoint = "sendPhoto"
            file_key = "photo"
        else:
            endpoint = "sendDocument"
            file_key = "document"

        with open(path, "rb") as f:
            payload = {"chat_id": target_chat}
            if caption:
                payload["caption"] = caption[:1024]  # Telegram caption limit
            resp = requests.post(
                f"{API_BASE}/{endpoint}",
                data=payload,
                files={file_key: (path.name, f)},
                timeout=30,
            )
        data = resp.json()
        if data.get("ok"):
            return f"✓ File '{path.name}' sent to Telegram"
        return f"ERROR: {data.get('description', 'Unknown error')}"
    except Exception as e:
        return f"ERROR sending file: {e}"


def _discover_chat_id():
    """Try to discover the chat ID from recent messages sent to the bot."""
    try:
        resp = requests.get(f"{API_BASE}/getUpdates", params={"limit": 10}, timeout=10)
        data = resp.json()
        if data.get("ok") and data.get("result"):
            # Get the most recent message's chat ID
            for update in reversed(data["result"]):
                msg = update.get("message", {})
                chat = msg.get("chat", {})
                chat_id = chat.get("id")
                if chat_id:
                    # Save it for future use
                    _save_chat_id(str(chat_id))
                    return str(chat_id)
    except Exception:
        pass
    return ""


def _save_chat_id(chat_id):
    """Save discovered chat ID to .env for future use."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    try:
        content = env_path.read_text()
        if "TELEGRAM_CHAT_ID" in content:
            # Update existing
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if line.startswith("TELEGRAM_CHAT_ID"):
                    lines[i] = f"TELEGRAM_CHAT_ID={chat_id}"
                    break
            env_path.write_text("\n".join(lines))
        else:
            # Append
            with open(env_path, "a") as f:
                f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")

        # Also update the module-level variable
        global TELEGRAM_CHAT_ID
        TELEGRAM_CHAT_ID = chat_id
    except Exception:
        pass


def _split_message(text):
    """Split a long message into chunks that fit Telegram's 4096 char limit."""
    if len(text) <= MAX_MSG_LEN:
        return [text]

    chunks = []
    while text:
        if len(text) <= MAX_MSG_LEN:
            chunks.append(text)
            break
        # Try to split at a newline near the limit
        split_at = text.rfind("\n", 0, MAX_MSG_LEN)
        if split_at == -1 or split_at < MAX_MSG_LEN // 2:
            split_at = MAX_MSG_LEN
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks


# Tool definitions for the AI agent
TOOL_DEFINITION_SEND = {
    "type": "function",
    "function": {
        "name": "send_telegram",
        "description": "Send a text message or report to the user's Telegram account. Supports Markdown formatting. Long messages are automatically split into multiple parts. Use this when the user asks you to send results, reports, or findings to their Telegram.",
        "parameters": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The text message to send. Supports Markdown: *bold*, _italic_, `code`, ```code block```. For reports, format nicely with headers and sections."
                },
                "parse_mode": {
                    "type": "string",
                    "enum": ["Markdown", "HTML", ""],
                    "description": "Message formatting mode. Default: Markdown",
                    "default": "Markdown"
                }
            },
            "required": ["message"]
        }
    }
}

TOOL_DEFINITION_FILE = {
    "type": "function",
    "function": {
        "name": "send_telegram_file",
        "description": "Send a file (report, image, screenshot) to the user's Telegram account. Use this to send saved report files, scan results, or any document the user wants on Telegram.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to send"
                },
                "caption": {
                    "type": "string",
                    "description": "Optional caption for the file (max 1024 chars)",
                    "default": ""
                }
            },
            "required": ["file_path"]
        }
    }
}
