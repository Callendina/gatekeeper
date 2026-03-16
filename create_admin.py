#!/usr/bin/env python3
"""Create or promote a user to system admin.

Since authentication is OAuth-only, this script can only promote
existing users (who have already signed in via Google or GitHub).
"""
import asyncio
import sys
from sqlalchemy import select
from gatekeeper.config import load_config
from gatekeeper.database import init_db, async_session_factory
from gatekeeper.models import User


async def main():
    if len(sys.argv) < 2:
        print("Usage: python create_admin.py <email>")
        print("  Promotes an existing user to system admin.")
        print("  The user must have signed in at least once via OAuth.")
        sys.exit(1)

    email = sys.argv[1]

    config = load_config()
    await init_db(config.database_path)

    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if user:
            user.is_system_admin = True
            await db.commit()
            print(f"Promoted {email} to system admin.")
        else:
            print(f"User {email} not found. They must sign in via OAuth first.")
            sys.exit(1)


asyncio.run(main())
