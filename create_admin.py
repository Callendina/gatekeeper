#!/usr/bin/env python3
"""Create or promote a user to system admin."""
import asyncio
import sys
from sqlalchemy import select
from gatekeeper.config import load_config
from gatekeeper.database import init_db, async_session_factory
from gatekeeper.models import User
from gatekeeper.auth.passwords import hash_password


async def main():
    if len(sys.argv) < 2:
        print("Usage: python create_admin.py <email> [password]")
        print("  If user exists, promotes to system admin.")
        print("  If user doesn't exist, creates with given password.")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else None

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
            if not password:
                print("User doesn't exist. Provide a password to create:")
                print(f"  python create_admin.py {email} <password>")
                sys.exit(1)
            user = User(
                email=email,
                password_hash=hash_password(password),
                display_name=email.split("@")[0],
                is_system_admin=True,
            )
            db.add(user)
            await db.commit()
            print(f"Created admin user: {email}")


asyncio.run(main())
