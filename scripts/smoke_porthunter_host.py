import asyncio
import os
from app.cli import handle_user_text

os.environ.setdefault("PORT_HUNTER_TOKEN","TEST_TOKEN")
os.environ.setdefault("PORT_HUNTER_ALLOWED_DIR",".")  # sandbox en repo

async def main():
    out = await handle_user_text("analiza ./tiny.pcap")
    print(out)

if __name__ == "__main__":
    asyncio.run(main())
