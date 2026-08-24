"""Simple data.db backup — copies the live SQLite file to backups/ with a
timestamped name. No automated scheduling here (that needs a real host —
cron/Task Scheduler/systemd timer once this is actually deployed somewhere,
not something this script can set up for you); run it manually or wire it
into whatever scheduler your host provides.

Usage: python backup_db.py [--keep N]   (keeps the N most recent backups, default 14)
"""

import shutil
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "data.db"
BACKUP_DIR = Path(__file__).parent / "backups"


def main():
    if not DB_PATH.exists():
        print(f"No {DB_PATH.name} found — nothing to back up yet.")
        return

    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = BACKUP_DIR / f"data-{stamp}.db"
    shutil.copy2(DB_PATH, dest)
    print(f"Backed up to {dest}")

    keep = 14
    if "--keep" in sys.argv:
        keep = int(sys.argv[sys.argv.index("--keep") + 1])
    backups = sorted(BACKUP_DIR.glob("data-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[keep:]:
        old.unlink()
        print(f"Pruned old backup: {old.name}")


if __name__ == "__main__":
    main()
