#!/usr/bin/env python3
"""
Admin Reset Script - Emergency admin account reset and recovery
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from db import execute, get_db_connection
from werkzeug.security import generate_password_hash

def reset_admin():
    """Reset admin user to default credentials"""
    
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    
    print(f"\n{'='*60}")
    print("🔧 ADMIN RESET UTILITY")
    print(f"{'='*60}\n")
    
    try:
        # Delete existing admin if exists
        print(f"🗑️  Removing existing admin user...")
        execute("DELETE FROM users WHERE username = ?", (admin_username,), commit=True)
        print("✅ Old admin user removed\n")
        
        # Create new admin
        print(f"👤 Creating new admin user: {admin_username}")
        password_hash = generate_password_hash(admin_password)
        execute(
            "INSERT INTO users (username, password_hash, role, approved, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (admin_username, password_hash, "admin", True),
            commit=True
        )
        print("✅ Admin user created\n")
        
        # Verify
        result = execute("SELECT * FROM users WHERE username = ?", (admin_username,), fetchone=True)
        if result:
            print("✅ Verification successful!\n")
            print(f"{'='*60}")
            print("📝 Login Credentials:")
            print(f"{'='*60}")
            print(f"Username: {admin_username}")
            print(f"Password: {admin_password}")
            print(f"{'='*60}\n")
            return 0
        else:
            print("❌ Admin creation failed!\n")
            return 1
            
    except Exception as e:
        print(f"❌ Error: {e}\n")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(reset_admin())
