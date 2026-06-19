#!/usr/bin/env python3
import os
import sys
import shutil
import gzip
import sqlite3
from datetime import datetime
from pathlib import Path

RENDER_DB_PATH = "parkwash.db"
BACKUP_DIR = "backups"
BACKUP_NAME = f"parkwash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db.gz"

def ensure_backup_dir():
    Path(BACKUP_DIR).mkdir(exist_ok=True)

def validate_database(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check")
        result = cur.fetchone()[0]
        conn.close()
        
        if result == "ok":
            print(f"✅ Database integrity check passed")
            return True
        else:
            print(f"❌ Database integrity check failed: {result}")
            return False
    except Exception as e:
        print(f"❌ Database validation error: {e}")
        return False

def create_backup(db_path, backup_path):
    try:
        if not os.path.exists(db_path):
            print(f"⚠️ Database not found at {db_path}")
            print("This is normal for first run or if database hasn't been initialized yet")
            return False
        
        if not validate_database(db_path):
            print("⚠️ Database validation failed, but continuing with backup")
        
        with open(db_path, 'rb') as f_in:
            with gzip.open(backup_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        file_size = os.path.getsize(backup_path)
        print(f"✅ Backup created: {backup_path} ({file_size} bytes)")
        return True
    
    except Exception as e:
        print(f"❌ Backup creation failed: {e}")
        return False

def keep_latest_backups(backup_dir, keep_count=24):
    try:
        backups = sorted(
            Path(backup_dir).glob("parkwash_*.db.gz"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        for old_backup in backups[keep_count:]:
            old_backup.unlink()
            print(f"🗑️ Deleted old backup: {old_backup.name}")
        
        print(f"📊 Total backups kept: {min(len(backups), keep_count)}")
    
    except Exception as e:
        print(f"⚠️ Error cleaning old backups: {e}")

def list_backups(backup_dir):
    try:
        backups = sorted(
            Path(backup_dir).glob("parkwash_*.db.gz"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        if not backups:
            print("No backups found")
            return
        
        print("\n📦 Available backups:")
        for i, backup in enumerate(backups, 1):
            size = backup.stat().st_size
            mtime = datetime.fromtimestamp(backup.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{i}. {backup.name} ({size} bytes) - {mtime}")
    
    except Exception as e:
        print(f"❌ Error listing backups: {e}")

def main():
    ensure_backup_dir()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "download":
            backup_path = os.path.join(BACKUP_DIR, BACKUP_NAME)
            if create_backup(RENDER_DB_PATH, backup_path):
                keep_latest_backups(BACKUP_DIR, keep_count=24)
                print(f"✅ Backup process completed successfully")
            else:
                print(f"⚠️ Backup process completed with warnings")
        
        elif command == "list":
            list_backups(BACKUP_DIR)
        
        elif command == "restore":
            if len(sys.argv) < 3:
                print("Usage: python backup.py restore <backup_filename>")
                sys.exit(1)
            
            backup_file = sys.argv[2]
            backup_path = os.path.join(BACKUP_DIR, backup_file)
            
            if not os.path.exists(backup_path):
                print(f"❌ Backup file not found: {backup_path}")
                sys.exit(1)
            
            try:
                with gzip.open(backup_path, 'rb') as f_in:
                    with open(RENDER_DB_PATH, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                print(f"✅ Database restored from {backup_file}")
            except Exception as e:
                print(f"❌ Restore failed: {e}")
                sys.exit(1)
        
        else:
            print("Unknown command. Use: download, list, or restore")
            sys.exit(1)
    
    else:
        backup_path = os.path.join(BACKUP_DIR, BACKUP_NAME)
        create_backup(RENDER_DB_PATH, backup_path)
        keep_latest_backups(BACKUP_DIR, keep_count=24)

if __name__ == "__main__":
    main()
