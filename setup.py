#!/usr/bin/env python
"""
Setup script for NETAD Finals - Networking Administration System
This script initializes the database and creates the admin user.
"""

import os
import sys
from pathlib import Path

# Add the app directory to the path FIRST
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables BEFORE importing db
from dotenv import load_dotenv
load_dotenv()

from db import init_db
from models import ensure_admin_user

def setup():
    """Initialize the database and admin user."""
    print("🔧 Setting up NETAD Finals System...")
    
    # Initialize database
    print("📦 Initializing database...")
    init_db()
    print("✅ Database initialized successfully!")
    
    # Create admin user
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    
    if not admin_username or not admin_password:
        print("❌ Error: ADMIN_USERNAME and ADMIN_PASSWORD must be set in .env file")
        sys.exit(1)
    
    print(f"👤 Creating admin user: {admin_username}...")
    ensure_admin_user(admin_username, admin_password)
    print(f"✅ Admin user created successfully!")
    
    print("\n" + "="*50)
    print("✨ Setup Complete!")
    print("="*50)
    print(f"\n📝 Login Credentials:")
    print(f"   Username: {admin_username}")
    print(f"   Password: {admin_password}")
    print("\n🚀 You can now run: python app.py")
    print("="*50 + "\n")

if __name__ == "__main__":
    setup()
