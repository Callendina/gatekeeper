"""Markdown → WhatsApp text converter.

WhatsApp uses a simplified markup that differs from Markdown:
  *text*  — bold   (Markdown: **text**)
  _text_  — italic (Markdown: *text* or _text_)
  ~text~  — strikethrough
  ```text``` — monospace (same as Markdown fenced blocks)

Tables and HTML are not supported; we flatten them to plain text.
Messages are truncated at 4096 chars (WhatsApp's message size limit).
"""
import re

_MAX_LEN = 4096


def to_whatsapp(md: str) -> str:
    """Convert markdown text to WhatsApp-formatted text."""
    text = md

    # ATX headings: # Heading → *Heading* (bold, no #)
    text = re.sub(r"^#{1,6}\s+(.+)$", r"*\1*", text, flags=re.MULTILINE)

    # Bold: **text** or __text__ → *text*
    text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text)
    text = re.sub(r"__(.+?)__", r"*\1*", text)

    # Italic: *text* (not already bold) → _text_
    # Only match single-asterisk not preceded/followed by another asterisk.
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"_\1_", text)

    # Fenced code blocks: ```lang\n...\n``` → ```...``` (strip language tag)
    text = re.sub(r"```[^\n]*\n(.*?)```", r"```\1```", text, flags=re.DOTALL)

    # Inline code: `code` — leave as-is (WhatsApp renders backtick monospace)

    # Tables: strip Markdown table syntax to plain text rows.
    # A table row looks like: | col | col | col |
    # The separator row (|---|---|) is dropped entirely.
    def _flatten_table(m: re.Match) -> str:
        lines = m.group(0).strip().splitlines()
        out = []
        for line in lines:
            if re.match(r"^\|[\s\-|:]+\|$", line):
                continue  # separator row
            cells = [c.strip() for c in line.strip("|").split("|")]
            out.append("  ".join(c for c in cells if c))
        return "\n".join(out)

    text = re.sub(r"(\|.+\|\n)+", _flatten_table, text)

    # Horizontal rules: --- / *** / ___ → blank line
    text = re.sub(r"^[-*_]{3,}\s*$", "", text, flags=re.MULTILINE)

    # Blockquotes: > text → text (strip >)
    text = re.sub(r"^>\s?", "", text, flags=re.MULTILINE)

    # Unordered list bullets: - item / * item → • item
    text = re.sub(r"^[\-\*]\s+", "• ", text, flags=re.MULTILINE)

    # Links: [text](url) → text (drop URL; WhatsApp auto-previews raw URLs)
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)

    # Collapse excess blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    text = text.strip()

    if len(text) > _MAX_LEN:
        text = text[:_MAX_LEN - 1] + "…"

    return text
