"""IP blocklist check — backed by DB with in-memory cache."""
import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from gatekeeper.models import IPBlocklist

# In-memory cache of blocked IPs, refreshed periodically
_blocked_ips: set[str] = set()
_last_refresh: datetime.datetime | None = None
_REFRESH_INTERVAL = datetime.timedelta(seconds=30)


async def refresh_blocklist(db: AsyncSession):
    global _blocked_ips, _last_refresh
    stmt = select(IPBlocklist.ip_address)
    result = await db.execute(stmt)
    _blocked_ips = {row[0] for row in result.all()}
    _last_refresh = datetime.datetime.utcnow()


async def is_ip_blocked(db: AsyncSession, ip: str) -> bool:
    global _last_refresh
    now = datetime.datetime.utcnow()
    if _last_refresh is None or (now - _last_refresh) > _REFRESH_INTERVAL:
        await refresh_blocklist(db)
    return ip in _blocked_ips


async def block_ip(db: AsyncSession, ip: str, reason: str = "", blocked_by: str = ""):
    existing = await db.execute(
        select(IPBlocklist).where(IPBlocklist.ip_address == ip)
    )
    if existing.scalar_one_or_none():
        return

    entry = IPBlocklist(ip_address=ip, reason=reason, blocked_by=blocked_by)
    db.add(entry)
    await db.commit()
    _blocked_ips.add(ip)


async def unblock_ip(db: AsyncSession, ip: str):
    from sqlalchemy import delete
    await db.execute(delete(IPBlocklist).where(IPBlocklist.ip_address == ip))
    await db.commit()
    _blocked_ips.discard(ip)
