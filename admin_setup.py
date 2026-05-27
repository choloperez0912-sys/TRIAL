#!/usr/bin/env python3
"""
NETAD Admin Setup and Verification Script
Ensures you are set as the system administrator with full control.
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import time

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

# Import after path setup
from db import init_db, get_db_connection, is_postgres
from models import (
    get_user_by_username, 
    ensure_admin_user, 
    create_user,
    get_allowed_ip,
    create_allowed_ip,
    execute
)
from werkzeug.security import generate_password_hash

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")

def print_success(msg):
    """Print success message"""
    print(f"✅ {msg}")

def print_error(msg):
    """Print error message"""
    print(f"❌ {msg}")

def print_info(msg):
    """Print info message"""
    print(f"ℹ️  {msg}")

def print_warning(msg):
    """Print warning message"""
    print(f"⚠️  {msg}")

def verify_database_connection():
    """Verify database connection"""
    print_header("1️⃣  Database Connection Verification")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if is_postgres():
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            print_success(f"PostgreSQL connected")
            print(f"   Version: {version[0] if version else 'Unknown'}\n")
        else:
            cursor.execute("SELECT sqlite_version();")
            version = cursor.fetchone()
            print_success(f"SQLite connected")
            print(f"   Version: {version[0] if version else 'Unknown'}\n")
        
        conn.close()
        return True
    except Exception as e:
        print_error(f"Database connection failed: {e}")
        return False

def verify_tables():
    """Verify all required tables exist"""
    print_header("2️⃣  Database Schema Verification")
    
    required_tables = [
        'users', 'logs', 'allowed_ips', 'blocked_ips',
        'login_requests', 'notifications', 'system_settings'
    ]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for table in required_tables:
            if is_postgres():
                cursor.execute(
                    f"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='{table}')"
                )
            else:
                cursor.execute(
                    f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"
                )
            
            exists = cursor.fetchone()
            if exists and (is_postgres() or exists[0]):
                print_success(f"Table '{table}' exists")
            else:
                print_error(f"Table '{table}' missing!")
                conn.close()
                return False
        
        conn.close()
        print()
        return True
    except Exception as e:
        print_error(f"Table verification failed: {e}")
        return False

def setup_admin_user():
    """Set up admin user with full privileges"""
    print_header("3️⃣  Admin User Setup")
    
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    
    print_info(f"Admin Username: {admin_username}")
    print_info(f"Admin Password: {'*' * len(admin_password)} (length: {len(admin_password)})\n")
    
    try:
        # Check if admin already exists
        admin = get_user_by_username(admin_username)
        
        if admin:
            print_warning(f"Admin user '{admin_username}' already exists")
            
            # Verify it has admin role
            if admin.get('role') == 'admin':
                print_success(f"User '{admin_username}' has ADMIN role ✓")
            else:
                print_error(f"User '{admin_username}' does NOT have admin role!")
                print_warning("Updating user to admin role...")
                execute(
                    "UPDATE users SET role = ? WHERE username = ?",
                    ("admin", admin_username),
                    commit=True
                )
                print_success("User role updated to admin")
            
            # Verify it's approved
            if admin.get('approved'):
                print_success(f"User '{admin_username}' is APPROVED ✓")
            else:
                print_error(f"User '{admin_username}' is NOT approved!")
                print_warning("Approving user...")
                execute(
                    "UPDATE users SET approved = ? WHERE username = ?",
                    (True, admin_username),
                    commit=True
                )
                print_success("User approved")
        else:
            print_info(f"Creating new admin user: {admin_username}...")
            ensure_admin_user(admin_username, admin_password)
            print_success(f"Admin user '{admin_username}' created")
        
        print()
        return True
    except Exception as e:
        print_error(f"Admin setup failed: {e}")
        return False

def whitelist_localhost():
    """Add localhost to allowed IPs for development"""
    print_header("4️⃣  Localhost Whitelist Setup")
    
    localhost_ips = ['127.0.0.1', '::1']
    
    try:
        for ip in localhost_ips:
            existing = get_allowed_ip(ip)
            if existing:
                print_warning(f"IP {ip} already whitelisted")
            else:
                create_allowed_ip(ip, label="Localhost - Development", approved_by="system")
                print_success(f"IP {ip} whitelisted")
        
        print()
        return True
    except Exception as e:
        print_error(f"Localhost whitelist failed: {e}")
        return False

def display_admin_info():
    """Display admin user information"""
    print_header("5️⃣  Admin User Information")
    
    try:
        admin_username = os.environ.get("ADMIN_USERNAME", "admin")
        admin = get_user_by_username(admin_username)
        
        if admin:
            print(f"Username:    {admin.get('username')}")
            print(f"Role:        {admin.get('role').upper()}")
            print(f"Approved:    {admin.get('approved')}")
            print(f"Created At:  {admin.get('created_at')}")
            print()
            return True
        else:
            print_error(f"Admin user '{admin_username}' not found")
            return False
    except Exception as e:
        print_error(f"Failed to retrieve admin info: {e}")
        return False

def display_login_credentials():
    """Display login credentials and access information"""
    print_header("6️⃣  Login Credentials & Access Information")
    
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    
    print("🔐 Credentials:")
    print(f"   Username: {admin_username}")
    print(f"   Password: {admin_password}")
    print()
    
    print("🌐 Access Endpoints:")
    print("   Login:     http://127.0.0.1:5000/auth/login")
    print("   Dashboard: http://127.0.0.1:5000/dashboard")
    print("   Admin:     http://127.0.0.1:5000/admin")
    print()
    
    print("📊 Administrator Capabilities:")
    print("   ✓ Manage user accounts")
    print("   ✓ Approve/deny login requests")
    print("   ✓ Manage IP whitelist and blacklist")
    print("   ✓ View activity logs")
    print("   ✓ Manage CCTV cameras")
    print("   ✓ Configure system settings")
    print("   ✓ Send notifications")
    print()

def run_full_setup():
    """Run complete admin setup"""
    print("\n")
    print_header("🚀 NETAD ADMINISTRATOR SETUP & VERIFICATION")
    
    steps = [
        ("Database Connection", verify_database_connection),
        ("Database Schema", verify_tables),
        ("Admin User Setup", setup_admin_user),
        ("Localhost Whitelist", whitelist_localhost),
        ("Admin Information", display_admin_info),
    ]
    
    results = []
    for step_name, step_func in steps:
        try:
            result = step_func()
            results.append((step_name, result))
        except Exception as e:
            print_error(f"{step_name} failed: {e}")
            results.append((step_name, False))
    
    # Final summary
    print_header("✨ SETUP SUMMARY")
    
    all_passed = True
    for step_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {step_name}")
        if not passed:
            all_passed = False
    
    print()
    
    if all_passed:
        print_success("All setup steps completed successfully!")
        print()
        display_login_credentials()
        print_header("🎉 YOU ARE NOW SYSTEM ADMINISTRATOR")
        print("✅ Full administrative control enabled")
        print("✅ All permissions granted")
        print("✅ Ready to manage the system")
        print()
        return 0
    else:
        print_error("Some setup steps failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = run_full_setup()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
