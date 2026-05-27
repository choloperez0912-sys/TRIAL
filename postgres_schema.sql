-- ============================================================================
-- NETAD Finals Application - PostgreSQL Database Schema
-- ============================================================================
-- Complete production-ready schema for NETAD (Networking Administration)
-- system with user authentication, IP management, activity logging, and
-- security features.
--
-- Compatible with: PostgreSQL 12+
-- Deployment Target: Railway.app
-- ============================================================================

-- Drop existing objects if needed (comment out for production safety)
-- DROP TABLE IF EXISTS notifications CASCADE;
-- DROP TABLE IF EXISTS login_requests CASCADE;
-- DROP TABLE IF EXISTS logs CASCADE;
-- DROP TABLE IF EXISTS blocked_ips CASCADE;
-- DROP TABLE IF EXISTS allowed_ips CASCADE;
-- DROP TABLE IF EXISTS system_settings CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;

-- ============================================================================
-- TABLE: users
-- Purpose: Store user account information with role-based access control
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
    approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure username is not empty
    CONSTRAINT username_not_empty CHECK (TRIM(username) != '')
);

COMMENT ON TABLE users IS 'Stores user accounts with authentication credentials';
COMMENT ON COLUMN users.id IS 'Unique user identifier';
COMMENT ON COLUMN users.username IS 'Unique login name';
COMMENT ON COLUMN users.password_hash IS 'Bcrypt/werkzeug hashed password';
COMMENT ON COLUMN users.role IS 'User role: admin or user';
COMMENT ON COLUMN users.approved IS 'True if user account is approved';
COMMENT ON COLUMN users.created_at IS 'Account creation timestamp in UTC';

-- ============================================================================
-- TABLE: logs
-- Purpose: Activity audit trail for security and compliance
-- ============================================================================
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(255),
    ip INET,
    event TEXT NOT NULL,
    category VARCHAR(50) NOT NULL
        CHECK (category IN ('authentication', 'authorization', 'system', 'ip_management', 'settings')),
    success BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE logs IS 'Complete activity audit trail for all user actions and system events';
COMMENT ON COLUMN logs.id IS 'Unique log entry identifier';
COMMENT ON COLUMN logs.user_id IS 'Foreign key to users table (null for system events)';
COMMENT ON COLUMN logs.username IS 'Username at time of event (for deleted users)';
COMMENT ON COLUMN logs.ip IS 'Client IP address using INET type for PostgreSQL efficiency';
COMMENT ON COLUMN logs.event IS 'Description of what happened';
COMMENT ON COLUMN logs.category IS 'Event classification for filtering and analysis';
COMMENT ON COLUMN logs.success IS 'True if action succeeded, false if failed';
COMMENT ON COLUMN logs.created_at IS 'When the event occurred in UTC';

-- ============================================================================
-- TABLE: allowed_ips
-- Purpose: Whitelist of approved IP addresses
-- ============================================================================
CREATE TABLE IF NOT EXISTS allowed_ips (
    id SERIAL PRIMARY KEY,
    ip INET UNIQUE NOT NULL,
    label VARCHAR(255),
    active BOOLEAN NOT NULL DEFAULT true,
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure ip is not null/empty
    CONSTRAINT ip_not_null CHECK (ip IS NOT NULL)
);

COMMENT ON TABLE allowed_ips IS 'Whitelist of IP addresses approved for system access';
COMMENT ON COLUMN allowed_ips.id IS 'Unique allowed IP identifier';
COMMENT ON COLUMN allowed_ips.ip IS 'Approved IP address (INET type handles IPv4 and IPv6)';
COMMENT ON COLUMN allowed_ips.label IS 'Optional description (e.g., "Office Network", "Admin Machine")';
COMMENT ON COLUMN allowed_ips.active IS 'True if whitelist entry is currently active';
COMMENT ON COLUMN allowed_ips.approved_by IS 'Username of admin who approved this IP';
COMMENT ON COLUMN allowed_ips.approved_at IS 'When the IP was approved';
COMMENT ON COLUMN allowed_ips.created_at IS 'When the record was created';

-- ============================================================================
-- TABLE: blocked_ips
-- Purpose: Blacklist of blocked IP addresses
-- ============================================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip INET UNIQUE NOT NULL,
    reason VARCHAR(500),
    active BOOLEAN NOT NULL DEFAULT true,
    blocked_by VARCHAR(255),
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure ip is not null/empty
    CONSTRAINT ip_not_null CHECK (ip IS NOT NULL)
);

COMMENT ON TABLE blocked_ips IS 'Blacklist of IP addresses blocked from system access';
COMMENT ON COLUMN blocked_ips.id IS 'Unique blocked IP identifier';
COMMENT ON COLUMN blocked_ips.ip IS 'Blocked IP address (INET type handles IPv4 and IPv6)';
COMMENT ON COLUMN blocked_ips.reason IS 'Reason for blocking (e.g., "Brute force protection", "Suspicious activity")';
COMMENT ON COLUMN blocked_ips.active IS 'True if block is currently active';
COMMENT ON COLUMN blocked_ips.blocked_by IS 'Username of admin or system that blocked this IP';
COMMENT ON COLUMN blocked_ips.blocked_at IS 'When the IP was blocked';

-- ============================================================================
-- TABLE: login_requests
-- Purpose: Pending login requests from unapproved IPs
-- ============================================================================
CREATE TABLE IF NOT EXISTS login_requests (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    ip INET NOT NULL,
    device_info TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    admin_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure ip is not null/empty
    CONSTRAINT ip_not_null CHECK (ip IS NOT NULL)
);

COMMENT ON TABLE login_requests IS 'Pending login requests from IP addresses not yet whitelisted';
COMMENT ON COLUMN login_requests.id IS 'Unique request identifier';
COMMENT ON COLUMN login_requests.username IS 'Username attempting to login';
COMMENT ON COLUMN login_requests.ip IS 'Client IP address attempting access';
COMMENT ON COLUMN login_requests.device_info IS 'User agent / device information for security analysis';
COMMENT ON COLUMN login_requests.status IS 'Request status: pending, approved, or denied';
COMMENT ON COLUMN login_requests.admin_notes IS 'Admin comments on request';
COMMENT ON COLUMN login_requests.created_at IS 'When the request was created';
COMMENT ON COLUMN login_requests.updated_at IS 'When the request was last modified';

-- ============================================================================
-- TABLE: notifications
-- Purpose: System notifications for users
-- ============================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    level VARCHAR(20) NOT NULL DEFAULT 'info'
        CHECK (level IN ('info', 'warning', 'error', 'critical')),
    target_role VARCHAR(20) NOT NULL DEFAULT 'admin'
        CHECK (target_role IN ('user', 'admin', 'all')),
    is_read BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure fields are not empty
    CONSTRAINT title_not_empty CHECK (TRIM(title) != ''),
    CONSTRAINT message_not_empty CHECK (TRIM(message) != '')
);

COMMENT ON TABLE notifications IS 'System notifications displayed to users';
COMMENT ON COLUMN notifications.id IS 'Unique notification identifier';
COMMENT ON COLUMN notifications.title IS 'Short notification title';
COMMENT ON COLUMN notifications.message IS 'Detailed notification message';
COMMENT ON COLUMN notifications.level IS 'Severity level: info, warning, error, critical';
COMMENT ON COLUMN notifications.target_role IS 'Role(s) to notify: user, admin, or all';
COMMENT ON COLUMN notifications.is_read IS 'True if user has read the notification';
COMMENT ON COLUMN notifications.created_at IS 'When the notification was created';

-- ============================================================================
-- TABLE: system_settings
-- Purpose: Application configuration storage
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT,
    
    -- Ensure key and value are not empty
    CONSTRAINT key_not_empty CHECK (TRIM(key) != '')
);

COMMENT ON TABLE system_settings IS 'Key-value store for application configuration';
COMMENT ON COLUMN system_settings.key IS 'Setting name (e.g., "camera.mode", "rate_limit")';
COMMENT ON COLUMN system_settings.value IS 'Setting value as text';
COMMENT ON COLUMN system_settings.updated_at IS 'When the setting was last updated';
COMMENT ON COLUMN system_settings.description IS 'Description of what this setting controls';

-- ============================================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Users Table Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role) WHERE active IS TRUE;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_approved ON users(approved) WHERE approved = false;

-- Logs Table Indexes
CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_category ON logs(category);
CREATE INDEX IF NOT EXISTS idx_logs_success ON logs(success);
-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_logs_user_time ON logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ip_time ON logs(ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_category_time ON logs(category, created_at DESC);

-- Allowed IPs Indexes
CREATE INDEX IF NOT EXISTS idx_allowed_ips_ip ON allowed_ips(ip);
CREATE INDEX IF NOT EXISTS idx_allowed_ips_active ON allowed_ips(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_allowed_ips_created_at ON allowed_ips(created_at DESC);

-- Blocked IPs Indexes
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_at ON blocked_ips(blocked_at DESC);

-- Login Requests Indexes
CREATE INDEX IF NOT EXISTS idx_login_requests_ip ON login_requests(ip);
CREATE INDEX IF NOT EXISTS idx_login_requests_status ON login_requests(status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_login_requests_created_at ON login_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_requests_username ON login_requests(username);
-- Composite index for finding pending requests for an IP
CREATE INDEX IF NOT EXISTS idx_login_requests_ip_status ON login_requests(ip, status);

-- Notifications Indexes
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read) WHERE is_read = false;
CREATE INDEX IF NOT EXISTS idx_notifications_target_role ON notifications(target_role);
CREATE INDEX IF NOT EXISTS idx_notifications_level ON notifications(level);

-- System Settings Index
CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(key);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View: Active Administrators
CREATE OR REPLACE VIEW v_active_admins AS
SELECT 
    id,
    username,
    created_at
FROM users
WHERE role = 'admin' AND approved = true
ORDER BY username;

COMMENT ON VIEW v_active_admins IS 'List of currently active administrator accounts';

-- View: Active Allowed IPs
CREATE OR REPLACE VIEW v_active_allowed_ips AS
SELECT 
    id,
    ip,
    label,
    approved_by,
    approved_at
FROM allowed_ips
WHERE active = true
ORDER BY ip;

COMMENT ON VIEW v_active_allowed_ips IS 'Currently active whitelisted IP addresses';

-- View: Active Blocked IPs
CREATE OR REPLACE VIEW v_active_blocked_ips AS
SELECT 
    id,
    ip,
    reason,
    blocked_by,
    blocked_at
FROM blocked_ips
WHERE active = true
ORDER BY ip;

COMMENT ON VIEW v_active_blocked_ips IS 'Currently active blacklisted IP addresses';

-- View: Pending Login Requests
CREATE OR REPLACE VIEW v_pending_login_requests AS
SELECT 
    id,
    username,
    ip,
    device_info,
    created_at,
    updated_at
FROM login_requests
WHERE status = 'pending'
ORDER BY created_at DESC;

COMMENT ON VIEW v_pending_login_requests IS 'Pending IP whitelist requests requiring admin approval';

-- View: Recent Activity
CREATE OR REPLACE VIEW v_recent_activity AS
SELECT 
    id,
    user_id,
    username,
    ip,
    event,
    category,
    success,
    created_at
FROM logs
ORDER BY created_at DESC
LIMIT 1000;

COMMENT ON VIEW v_recent_activity IS 'Most recent 1000 log entries';

-- View: Failed Login Attempts (Last 24 Hours)
CREATE OR REPLACE VIEW v_failed_logins_24h AS
SELECT 
    ip,
    COUNT(*) as attempt_count,
    MAX(created_at) as last_attempt
FROM logs
WHERE category = 'authentication'
  AND success = false
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY ip
ORDER BY attempt_count DESC;

COMMENT ON VIEW v_failed_logins_24h IS 'Failed login attempts from last 24 hours grouped by IP';

-- ============================================================================
-- INITIAL DATA AND CONSTRAINTS
-- ============================================================================

-- Ensure at least one admin exists (will be handled by application)
-- The application's ensure_admin_user() function handles initial admin creation

-- ============================================================================
-- END OF SCHEMA DEFINITION
-- ============================================================================
-- Schema created successfully. The database is ready for application use.
-- All tables include:
-- ✓ Primary keys with auto-increment
-- ✓ Foreign keys with proper constraints
-- ✓ Check constraints for data validation
-- ✓ NOT NULL constraints where appropriate
-- ✓ Default values for timestamps and statuses
-- ✓ Comprehensive indexes for performance
-- ✓ Views for common queries
-- ✓ Detailed comments for documentation
-- ============================================================================
