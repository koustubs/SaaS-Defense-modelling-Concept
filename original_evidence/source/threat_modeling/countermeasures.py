#!/usr/bin/env python3
"""
Countermeasures and Solutions for Threat Modeling Findings
========================================================

This module provides detailed countermeasures and implementation guidance
for each threat identified in the threat modeling analysis.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class ImplementationPriority(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ImplementationEffort(Enum):
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"


@dataclass
class Countermeasure:
    """Represents a countermeasure for a specific threat."""
    threat_id: str
    threat_title: str
    countermeasure_id: str
    title: str
    description: str
    implementation_steps: List[str]
    code_examples: List[str]
    priority: ImplementationPriority
    effort: ImplementationEffort
    estimated_time: str
    dependencies: List[str]
    testing_requirements: List[str]
    monitoring_requirements: List[str]


class ThreatCountermeasures:
    """Provides countermeasures for all identified threats."""
    
    def __init__(self):
        self.countermeasures = self._initialize_countermeasures()
    
    def _initialize_countermeasures(self) -> Dict[str, List[Countermeasure]]:
        """Initialize all countermeasures for the identified threats."""
        
        countermeasures = {
            "TF-SD-003": [  # Resource exhaustion through unlimited operations
                Countermeasure(
                    threat_id="TF-SD-003",
                    threat_title="Resource exhaustion through unlimited operations",
                    countermeasure_id="CM-003-001",
                    title="Implement Rate Limiting",
                    description="Implement comprehensive rate limiting across all API endpoints to prevent resource exhaustion attacks.",
                    implementation_steps=[
                        "1. Install and configure a rate limiting middleware (e.g., Redis-based)",
                        "2. Define rate limits per endpoint and user/IP",
                        "3. Implement sliding window rate limiting algorithm",
                        "4. Add rate limit headers to responses",
                        "5. Configure different limits for authenticated vs unauthenticated users",
                        "6. Set up monitoring and alerting for rate limit violations"
                    ],
                    code_examples=[
                        "# Rate limiting middleware example\n"
                        "from flask_limiter import Limiter\n"
                        "from flask_limiter.util import get_remote_address\n\n"
                        "limiter = Limiter(\n"
                        "    app,\n"
                        "    key_func=get_remote_address,\n"
                        "    default_limits=[\"200 per day\", \"50 per hour\"]\n"
                        ")\n\n"
                        "@app.route('/api/notes')\n"
                        "@limiter.limit(\"10 per minute\")\n"
                        "def get_notes():\n"
                        "    # API implementation\n"
                        "    pass"
                    ],
                    priority=ImplementationPriority.CRITICAL,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="2-3 days",
                    dependencies=["Redis server", "Rate limiting library"],
                    testing_requirements=[
                        "Load testing with various request patterns",
                        "Verify rate limits are enforced correctly",
                        "Test rate limit bypass attempts",
                        "Performance impact assessment"
                    ],
                    monitoring_requirements=[
                        "Monitor rate limit violations",
                        "Track API response times",
                        "Alert on unusual traffic patterns",
                        "Monitor resource usage during attacks"
                    ]
                ),
                Countermeasure(
                    threat_id="TF-SD-003",
                    threat_title="Resource exhaustion through unlimited operations",
                    countermeasure_id="CM-003-002",
                    title="Implement Resource Quotas",
                    description="Set up resource quotas and limits to prevent system exhaustion.",
                    implementation_steps=[
                        "1. Define resource quotas per user/tenant",
                        "2. Implement database connection pooling",
                        "3. Set memory and CPU limits per request",
                        "4. Configure timeout limits for long-running operations",
                        "5. Implement circuit breakers for external services",
                        "6. Add resource usage monitoring"
                    ],
                    code_examples=[
                        "# Resource quota example\n"
                        "class ResourceQuota:\n"
                        "    def __init__(self, max_requests=1000, max_memory_mb=512):\n"
                        "        self.max_requests = max_requests\n"
                        "        self.max_memory_mb = max_memory_mb\n\n"
                        "    def check_quota(self, user_id):\n"
                        "        # Check if user has exceeded quota\n"
                        "        current_usage = self.get_user_usage(user_id)\n"
                        "        return current_usage < self.max_requests\n\n"
                        "    def enforce_quota(self, user_id):\n"
                        "        if not self.check_quota(user_id):\n"
                        "            raise QuotaExceededError(\"Resource quota exceeded\")"
                    ],
                    priority=ImplementationPriority.CRITICAL,
                    effort=ImplementationEffort.HARD,
                    estimated_time="1-2 weeks",
                    dependencies=["Monitoring system", "Database optimization"],
                    testing_requirements=[
                        "Stress testing with quota limits",
                        "Verify quota enforcement",
                        "Test quota bypass attempts",
                        "Performance impact assessment"
                    ],
                    monitoring_requirements=[
                        "Monitor resource usage per user",
                        "Track quota violations",
                        "Alert on resource exhaustion",
                        "Monitor system performance"
                    ]
                )
            ],
            
            "TF-SD-004": [  # User can access admin functions without proper authorization
                Countermeasure(
                    threat_id="TF-SD-004",
                    threat_title="User can access admin functions without proper authorization",
                    countermeasure_id="CM-004-001",
                    title="Implement Role-Based Access Control (RBAC)",
                    description="Implement comprehensive RBAC system to control access to administrative functions.",
                    implementation_steps=[
                        "1. Define user roles and permissions",
                        "2. Implement role-based middleware",
                        "3. Add permission checks to all admin endpoints",
                        "4. Implement audit logging for admin actions",
                        "5. Add role validation on authentication",
                        "6. Create admin-only API endpoints"
                    ],
                    code_examples=[
                        "# RBAC implementation example\n"
                        "from functools import wraps\n"
                        "from flask import request, abort\n\n"
                        "def require_role(role):\n"
                        "    def decorator(f):\n"
                        "        @wraps(f)\n"
                        "        def decorated_function(*args, **kwargs):\n"
                        "            user = get_current_user()\n"
                        "            if not user or role not in user.roles:\n"
                        "                abort(403, description=\"Insufficient permissions\")\n"
                        "            return f(*args, **kwargs)\n"
                        "        return decorated_function\n"
                        "    return decorator\n\n"
                        "@app.route('/api/notes/export')\n"
                        "@require_role('admin')\n"
                        "def export_notes():\n"
                        "    # Admin-only export functionality\n"
                        "    pass"
                    ],
                    priority=ImplementationPriority.CRITICAL,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="3-5 days",
                    dependencies=["Authentication system", "Database schema updates"],
                    testing_requirements=[
                        "Test role-based access controls",
                        "Verify admin function protection",
                        "Test privilege escalation attempts",
                        "Audit log verification"
                    ],
                    monitoring_requirements=[
                        "Monitor admin function access",
                        "Track permission violations",
                        "Alert on unauthorized access attempts",
                        "Audit log monitoring"
                    ]
                ),
                Countermeasure(
                    threat_id="TF-SD-004",
                    threat_title="User can access admin functions without proper authorization",
                    countermeasure_id="CM-004-002",
                    title="Implement API Gateway Authorization",
                    description="Add authorization layer at the API gateway level.",
                    implementation_steps=[
                        "1. Configure API gateway with authorization policies",
                        "2. Implement JWT token validation with roles",
                        "3. Add request filtering based on user roles",
                        "4. Implement API key management for admin access",
                        "5. Add request logging for admin endpoints",
                        "6. Configure rate limiting for admin functions"
                    ],
                    code_examples=[
                        "# API Gateway authorization example\n"
                        "def validate_admin_token(token):\n"
                        "    try:\n"
                        "        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
                        "        return payload.get('role') == 'admin'\n"
                        "    except:\n"
                        "        return False\n\n"
                        "def admin_middleware(request):\n"
                        "    if request.path.startswith('/api/admin/'):\n"
                        "        token = request.headers.get('Authorization')\n"
                        "        if not validate_admin_token(token):\n"
                        "            return {'error': 'Unauthorized'}, 403\n"
                        "    return None"
                    ],
                    priority=ImplementationPriority.CRITICAL,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="2-3 days",
                    dependencies=["API Gateway", "JWT implementation"],
                    testing_requirements=[
                        "Test gateway authorization",
                        "Verify admin endpoint protection",
                        "Test token validation",
                        "Performance impact assessment"
                    ],
                    monitoring_requirements=[
                        "Monitor admin endpoint access",
                        "Track authorization failures",
                        "Alert on unauthorized admin access",
                        "Monitor gateway performance"
                    ]
                )
            ],
            
            "TF-SD-002": [  # No rate limiting on API endpoints
                Countermeasure(
                    threat_id="TF-SD-002",
                    threat_title="No rate limiting on API endpoints",
                    countermeasure_id="CM-002-001",
                    title="Implement Comprehensive Rate Limiting",
                    description="Implement rate limiting across all API endpoints with different strategies.",
                    implementation_steps=[
                        "1. Implement IP-based rate limiting",
                        "2. Add user-based rate limiting for authenticated requests",
                        "3. Configure different limits for different endpoints",
                        "4. Implement adaptive rate limiting",
                        "5. Add rate limit headers to responses",
                        "6. Set up rate limit monitoring and alerting"
                    ],
                    code_examples=[
                        "# Comprehensive rate limiting example\n"
                        "from flask_limiter import Limiter\n"
                        "from flask_limiter.util import get_remote_address\n\n"
                        "limiter = Limiter(\n"
                        "    app,\n"
                        "    key_func=get_remote_address,\n"
                        "    storage_uri=\"redis://localhost:6379\"\n"
                        ")\n\n"
                        "# Different limits for different endpoints\n"
                        "@app.route('/api/login')\n"
                        "@limiter.limit(\"5 per minute\")\n"
                        "def login():\n"
                        "    pass\n\n"
                        "@app.route('/api/notes')\n"
                        "@limiter.limit(\"100 per hour\")\n"
                        "def get_notes():\n"
                        "    pass\n\n"
                        "@app.route('/api/notes/create')\n"
                        "@limiter.limit(\"50 per hour\")\n"
                        "def create_note():\n"
                        "    pass"
                    ],
                    priority=ImplementationPriority.HIGH,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="2-3 days",
                    dependencies=["Redis server", "Rate limiting library"],
                    testing_requirements=[
                        "Test rate limiting enforcement",
                        "Verify different limits per endpoint",
                        "Test rate limit bypass attempts",
                        "Performance impact assessment"
                    ],
                    monitoring_requirements=[
                        "Monitor rate limit violations",
                        "Track API usage patterns",
                        "Alert on unusual traffic",
                        "Monitor Redis performance"
                    ]
                )
            ],
            
            "TF-SD-005": [  # Session management without proper timeout
                Countermeasure(
                    threat_id="TF-SD-005",
                    threat_title="Session management without proper timeout",
                    countermeasure_id="CM-005-001",
                    title="Implement Secure Session Management",
                    description="Implement comprehensive session management with proper timeouts and security measures.",
                    implementation_steps=[
                        "1. Implement session timeouts (15-30 minutes)",
                        "2. Add session invalidation on logout",
                        "3. Implement session rotation on privilege changes",
                        "4. Add session binding to IP/user agent",
                        "5. Implement concurrent session limits",
                        "6. Add session audit logging"
                    ],
                    code_examples=[
                        "# Secure session management example\n"
                        "from datetime import datetime, timedelta\n"
                        "import secrets\n\n"
                        "class SecureSession:\n"
                        "    def __init__(self):\n"
                        "        self.session_timeout = timedelta(minutes=30)\n"
                        "        self.max_concurrent_sessions = 3\n\n"
                        "    def create_session(self, user_id, ip_address, user_agent):\n"
                        "        session_id = secrets.token_urlsafe(32)\n"
                        "        session_data = {\n"
                        "            'user_id': user_id,\n"
                        "            'ip_address': ip_address,\n"
                        "            'user_agent': user_agent,\n"
                        "            'created_at': datetime.utcnow(),\n"
                        "            'last_activity': datetime.utcnow()\n"
                        "        }\n"
                        "        # Store in Redis with TTL\n"
                        "        redis_client.setex(f\"session:{session_id}\", \n"
                        "                           int(self.session_timeout.total_seconds()), \n"
                        "                           json.dumps(session_data))\n"
                        "        return session_id\n\n"
                        "    def validate_session(self, session_id, ip_address, user_agent):\n"
                        "        session_data = redis_client.get(f\"session:{session_id}\")\n"
                        "        if not session_data:\n"
                        "            return None\n"
                        "        \n"
                        "        data = json.loads(session_data)\n"
                        "        if data['ip_address'] != ip_address or data['user_agent'] != user_agent:\n"
                        "            self.invalidate_session(session_id)\n"
                        "            return None\n"
                        "        \n"
                        "        # Update last activity\n"
                        "        data['last_activity'] = datetime.utcnow().isoformat()\n"
                        "        redis_client.setex(f\"session:{session_id}\", \n"
                        "                           int(self.session_timeout.total_seconds()), \n"
                        "                           json.dumps(data))\n"
                        "        return data"
                    ],
                    priority=ImplementationPriority.HIGH,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="3-4 days",
                    dependencies=["Redis server", "Session management library"],
                    testing_requirements=[
                        "Test session timeout functionality",
                        "Verify session invalidation",
                        "Test session hijacking prevention",
                        "Concurrent session testing"
                    ],
                    monitoring_requirements=[
                        "Monitor session creation/destruction",
                        "Track session timeout events",
                        "Alert on suspicious session activity",
                        "Monitor Redis session storage"
                    ]
                )
            ],
            
            "TF-SD-001": [  # Sensitive data exposed in error messages
                Countermeasure(
                    threat_id="TF-SD-001",
                    threat_title="Sensitive data exposed in error messages",
                    countermeasure_id="CM-001-001",
                    title="Implement Secure Error Handling",
                    description="Implement secure error handling that doesn't expose sensitive information.",
                    implementation_steps=[
                        "1. Create centralized error handling middleware",
                        "2. Implement error message sanitization",
                        "3. Add error logging without sensitive data",
                        "4. Implement different error responses for dev/prod",
                        "5. Add input validation with safe error messages",
                        "6. Implement error tracking and monitoring"
                    ],
                    code_examples=[
                        "# Secure error handling example\n"
                        "import logging\n"
                        "from flask import Flask, jsonify\n"
                        "from werkzeug.exceptions import HTTPException\n\n"
                        "class SecureErrorHandler:\n"
                        "    def __init__(self, app, is_production=True):\n"
                        "        self.app = app\n"
                        "        self.is_production = is_production\n"
                        "        self.setup_error_handlers()\n\n"
                        "    def setup_error_handlers(self):\n"
                        "        @self.app.errorhandler(Exception)\n"
                        "        def handle_exception(e):\n"
                        "            # Log the full error for debugging\n"
                        "            logging.error(f\"Unhandled exception: {str(e)}\", exc_info=True)\n"
                        "            \n"
                        "            if self.is_production:\n"
                        "                return jsonify({\n"
                        "                    'error': 'An internal error occurred',\n"
                        "                    'error_code': 'INTERNAL_ERROR'\n"
                        "                }), 500\n"
                        "            else:\n"
                        "                return jsonify({\n"
                        "                    'error': str(e),\n"
                        "                    'type': type(e).__name__\n"
                        "                }), 500\n\n"
                        "    def sanitize_error_message(self, message):\n"
                        "        # Remove sensitive information from error messages\n"
                        "        sensitive_patterns = [\n"
                        "            r'password.*invalid',\n"
                        "            r'token.*invalid',\n"
                        "            r'secret.*exposed'\n"
                        "        ]\n"
                        "        \n"
                        "        for pattern in sensitive_patterns:\n"
                        "            message = re.sub(pattern, 'Invalid input', message, flags=re.IGNORECASE)\n"
                        "        \n"
                        "        return message"
                    ],
                    priority=ImplementationPriority.HIGH,
                    effort=ImplementationEffort.EASY,
                    estimated_time="1-2 days",
                    dependencies=["Logging system", "Error tracking service"],
                    testing_requirements=[
                        "Test error message sanitization",
                        "Verify no sensitive data exposure",
                        "Test error logging functionality",
                        "Environment-specific error testing"
                    ],
                    monitoring_requirements=[
                        "Monitor error rates",
                        "Track error message patterns",
                        "Alert on potential data exposure",
                        "Monitor error logging"
                    ]
                )
            ],
            
            "TF-SD-006": [  # No multi-factor authentication (MFA) option
                Countermeasure(
                    threat_id="TF-SD-006",
                    threat_title="No multi-factor authentication (MFA) option",
                    countermeasure_id="CM-006-001",
                    title="Implement Multi-Factor Authentication",
                    description="Implement MFA using TOTP (Time-based One-Time Password) for enhanced security.",
                    implementation_steps=[
                        "1. Integrate TOTP library (e.g., pyotp)",
                        "2. Add MFA setup during registration",
                        "3. Implement QR code generation for authenticator apps",
                        "4. Add MFA verification during login",
                        "5. Implement backup codes for account recovery",
                        "6. Add MFA bypass for trusted devices"
                    ],
                    code_examples=[
                        "# MFA implementation example\n"
                        "import pyotp\n"
                        "import qrcode\n"
                        "from io import BytesIO\n"
                        "import base64\n\n"
                        "class MFAService:\n"
                        "    def __init__(self):\n"
                        "        self.backup_codes_count = 10\n\n"
                        "    def generate_secret(self, user_id):\n"
                        "        # Generate unique secret for user\n"
                        "        secret = pyotp.random_base32()\n"
                        "        return secret\n\n"
                        "    def generate_qr_code(self, secret, user_email):\n"
                        "        # Generate QR code for authenticator apps\n"
                        "        totp = pyotp.TOTP(secret)\n"
                        "        provisioning_uri = totp.provisioning_uri(\n"
                        "            name=user_email,\n"
                        "            issuer_name=\"Your App Name\"\n"
                        "        )\n"
                        "        \n"
                        "        # Create QR code\n"
                        "        qr = qrcode.QRCode(version=1, box_size=10, border=5)\n"
                        "        qr.add_data(provisioning_uri)\n"
                        "        qr.make(fit=True)\n"
                        "        \n"
                        "        img = qr.make_image(fill_color=\"black\", back_color=\"white\")\n"
                        "        buffer = BytesIO()\n"
                        "        img.save(buffer, format='PNG')\n"
                        "        return base64.b64encode(buffer.getvalue()).decode()\n\n"
                        "    def verify_totp(self, secret, token):\n"
                        "        totp = pyotp.TOTP(secret)\n"
                        "        return totp.verify(token)\n\n"
                        "    def generate_backup_codes(self):\n"
                        "        # Generate backup codes for account recovery\n"
                        "        codes = []\n"
                        "        for _ in range(self.backup_codes_count):\n"
                        "            code = ''.join([str(random.randint(0, 9)) for _ in range(8)])\n"
                        "            codes.append(code)\n"
                        "        return codes"
                    ],
                    priority=ImplementationPriority.HIGH,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="1-2 weeks",
                    dependencies=["TOTP library", "QR code library", "Database schema updates"],
                    testing_requirements=[
                        "Test MFA setup process",
                        "Verify TOTP generation and validation",
                        "Test backup code functionality",
                        "Test MFA bypass scenarios"
                    ],
                    monitoring_requirements=[
                        "Monitor MFA adoption rates",
                        "Track MFA verification success/failure",
                        "Alert on MFA bypass attempts",
                        "Monitor backup code usage"
                    ]
                )
            ],
            
            "TF-SD-007": [  # No account lockout after repeated failed logins
                Countermeasure(
                    threat_id="TF-SD-007",
                    threat_title="No account lockout after repeated failed logins",
                    countermeasure_id="CM-007-001",
                    title="Implement Account Lockout and CAPTCHA",
                    description="Implement account lockout mechanisms and CAPTCHA to prevent brute force attacks.",
                    implementation_steps=[
                        "1. Implement failed login attempt tracking",
                        "2. Add account lockout after 5 failed attempts",
                        "3. Implement progressive delays (1min, 5min, 15min, 30min)",
                        "4. Add CAPTCHA after 3 failed attempts",
                        "5. Implement account unlock mechanisms",
                        "6. Add notification emails for lockouts"
                    ],
                    code_examples=[
                        "# Account lockout implementation example\n"
                        "from datetime import datetime, timedelta\n"
                        "import redis\n\n"
                        "class AccountLockout:\n"
                        "    def __init__(self):\n"
                        "        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)\n"
                        "        self.max_attempts = 5\n"
                        "        self.lockout_durations = [60, 300, 900, 1800]  # seconds\n\n"
                        "    def record_failed_attempt(self, username, ip_address):\n"
                        "        key = f\"failed_attempts:{username}:{ip_address}\"\n"
                        "        attempts = self.redis_client.get(key)\n"
                        "        \n"
                        "        if attempts is None:\n"
                        "            attempts = 1\n"
                        "        else:\n"
                        "            attempts = int(attempts) + 1\n"
                        "        \n"
                        "        # Set TTL based on attempt count\n"
                        "        ttl = min(attempts * 60, 3600)  # Max 1 hour\n"
                        "        self.redis_client.setex(key, ttl, attempts)\n"
                        "        \n"
                        "        return attempts\n\n"
                        "    def is_account_locked(self, username, ip_address):\n"
                        "        key = f\"failed_attempts:{username}:{ip_address}\"\n"
                        "        attempts = self.redis_client.get(key)\n"
                        "        \n"
                        "        if attempts is None:\n"
                        "            return False\n"
                        "        \n"
                        "        attempts = int(attempts)\n"
                        "        if attempts >= self.max_attempts:\n"
                        "            # Calculate lockout duration\n"
                        "            lockout_index = min(attempts - self.max_attempts, \n"
                        "                               len(self.lockout_durations) - 1)\n"
                        "            lockout_duration = self.lockout_durations[lockout_index]\n"
                        "            \n"
                        "            # Check if still in lockout period\n"
                        "            lockout_key = f\"lockout:{username}:{ip_address}\"\n"
                        "            lockout_time = self.redis_client.get(lockout_key)\n"
                        "            \n"
                        "            if lockout_time is None:\n"
                        "                # Start lockout period\n"
                        "                self.redis_client.setex(lockout_key, lockout_duration, \n"
                        "                                       datetime.utcnow().timestamp())\n"
                        "                return True\n"
                        "            else:\n"
                        "                # Check if lockout period has expired\n"
                        "                lockout_start = float(lockout_time)\n"
                        "                if datetime.utcnow().timestamp() - lockout_start < lockout_duration:\n"
                        "                    return True\n"
                        "                else:\n"
                        "                    # Clear lockout\n"
                        "                    self.redis_client.delete(lockout_key)\n"
                        "                    self.redis_client.delete(key)\n"
                        "                    return False\n"
                        "        \n"
                        "        return False\n\n"
                        "    def requires_captcha(self, username, ip_address):\n"
                        "        key = f\"failed_attempts:{username}:{ip_address}\"\n"
                        "        attempts = self.redis_client.get(key)\n"
                        "        return attempts is not None and int(attempts) >= 3"
                    ],
                    priority=ImplementationPriority.MEDIUM,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="2-3 days",
                    dependencies=["Redis server", "CAPTCHA service"],
                    testing_requirements=[
                        "Test account lockout functionality",
                        "Verify progressive delays",
                        "Test CAPTCHA integration",
                        "Test unlock mechanisms"
                    ],
                    monitoring_requirements=[
                        "Monitor failed login attempts",
                        "Track account lockouts",
                        "Alert on brute force patterns",
                        "Monitor CAPTCHA usage"
                    ]
                )
            ],
            
            "TF-SD-009": [  # No password strength indicator
                Countermeasure(
                    threat_id="TF-SD-009",
                    threat_title="No password strength indicator",
                    countermeasure_id="CM-009-001",
                    title="Implement Password Strength Indicator",
                    description="Implement real-time password strength validation and visual feedback.",
                    implementation_steps=[
                        "1. Implement password strength algorithm",
                        "2. Add real-time strength validation",
                        "3. Create visual strength indicator",
                        "4. Add password requirements display",
                        "5. Implement client-side validation",
                        "6. Add server-side password validation"
                    ],
                    code_examples=[
                        "# Password strength indicator example\n"
                        "import re\n"
                        "import zxcvbn\n\n"
                        "class PasswordStrength:\n"
                        "    def __init__(self):\n"
                        "        self.min_length = 8\n"
                        "        self.require_uppercase = True\n"
                        "        self.require_lowercase = True\n"
                        "        self.require_numbers = True\n"
                        "        self.require_special = True\n\n"
                        "    def check_strength(self, password):\n"
                        "        score = 0\n"
                        "        feedback = []\n"
                        "        \n"
                        "        # Length check\n"
                        "        if len(password) >= self.min_length:\n"
                        "            score += 1\n"
                        "        else:\n"
                        "            feedback.append(f\"Password must be at least {self.min_length} characters\")\n"
                        "        \n"
                        "        # Character type checks\n"
                        "        if re.search(r'[A-Z]', password):\n"
                        "            score += 1\n"
                        "        else:\n"
                        "            feedback.append(\"Include uppercase letters\")\n"
                        "        \n"
                        "        if re.search(r'[a-z]', password):\n"
                        "            score += 1\n"
                        "        else:\n"
                        "            feedback.append(\"Include lowercase letters\")\n"
                        "        \n"
                        "        if re.search(r'\\d', password):\n"
                        "            score += 1\n"
                        "        else:\n"
                        "            feedback.append(\"Include numbers\")\n"
                        "        \n"
                        "        if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):\n"
                        "            score += 1\n"
                        "        else:\n"
                        "            feedback.append(\"Include special characters\")\n"
                        "        \n"
                        "        # Use zxcvbn for additional strength analysis\n"
                        "        zxcvbn_result = zxcvbn.zxcvbn(password)\n"
                        "        \n"
                        "        # Combine scores\n"
                        "        final_score = min(score + zxcvbn_result['score'], 5)\n"
                        "        \n"
                        "        strength_levels = {\n"
                        "            0: \"Very Weak\",\n"
                        "            1: \"Weak\",\n"
                        "            2: \"Fair\",\n"
                        "            3: \"Good\",\n"
                        "            4: \"Strong\",\n"
                        "            5: \"Very Strong\"\n"
                        "        }\n"
                        "        \n"
                        "        return {\n"
                        "            'score': final_score,\n"
                        "            'level': strength_levels[final_score],\n"
                        "            'feedback': feedback,\n"
                        "            'zxcvbn_score': zxcvbn_result['score'],\n"
                        "            'zxcvbn_feedback': zxcvbn_result['feedback']['warning']\n"
                        "        }\n\n"
                        "# Frontend JavaScript example\n"
                        "'''\n"
                        "function updatePasswordStrength(password) {\n"
                        "    fetch('/api/password/strength', {\n"
                        "        method: 'POST',\n"
                        "        headers: {'Content-Type': 'application/json'},\n"
                        "        body: JSON.stringify({password: password})\n"
                        "    })\n"
                        "    .then(response => response.json())\n"
                        "    .then(data => {\n"
                        "        const strengthBar = document.getElementById('strength-bar');\n"
                        "        const strengthText = document.getElementById('strength-text');\n"
                        "        \n"
                        "        strengthBar.style.width = (data.score * 20) + '%';\n"
                        "        strengthBar.className = 'strength-bar ' + data.level.toLowerCase().replace(' ', '-');\n"
                        "        strengthText.textContent = data.level;\n"
                        "        \n"
                        "        // Show feedback\n"
                        "        const feedbackList = document.getElementById('feedback-list');\n"
                        "        feedbackList.innerHTML = '';\n"
                        "        data.feedback.forEach(item => {\n"
                        "            const li = document.createElement('li');\n"
                        "            li.textContent = item;\n"
                        "            feedbackList.appendChild(li);\n"
                        "        });\n"
                        "    });\n"
                        "}\n"
                        "'''"
                    ],
                    priority=ImplementationPriority.MEDIUM,
                    effort=ImplementationEffort.EASY,
                    estimated_time="1-2 days",
                    dependencies=["zxcvbn library", "Frontend framework"],
                    testing_requirements=[
                        "Test password strength algorithm",
                        "Verify visual feedback",
                        "Test various password combinations",
                        "Cross-browser compatibility testing"
                    ],
                    monitoring_requirements=[
                        "Monitor password strength distribution",
                        "Track password change patterns",
                        "Monitor user feedback",
                        "Track password-related support tickets"
                    ]
                )
            ],
            
            "TF-SD-008": [  # No new device login notification
                Countermeasure(
                    threat_id="TF-SD-008",
                    threat_title="No new device login notification",
                    countermeasure_id="CM-008-001",
                    title="Implement New Device Detection and Notifications",
                    description="Implement device fingerprinting and notification system for new device logins.",
                    implementation_steps=[
                        "1. Implement device fingerprinting",
                        "2. Add device tracking and storage",
                        "3. Implement email notification system",
                        "4. Add device approval workflow",
                        "5. Implement device blocking capabilities",
                        "6. Add device management interface"
                    ],
                    code_examples=[
                        "# Device detection and notification example\n"
                        "import hashlib\n"
                        "import json\n"
                        "from datetime import datetime\n"
                        "import smtplib\n"
                        "from email.mime.text import MIMEText\n\n"
                        "class DeviceManager:\n"
                        "    def __init__(self):\n"
                        "        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)\n\n"
                        "    def generate_device_fingerprint(self, request):\n"
                        "        # Create device fingerprint from request data\n"
                        "        fingerprint_data = {\n"
                        "            'user_agent': request.headers.get('User-Agent', ''),\n"
                        "            'ip_address': request.remote_addr,\n"
                        "            'accept_language': request.headers.get('Accept-Language', ''),\n"
                        "            'accept_encoding': request.headers.get('Accept-Encoding', ''),\n"
                        "            'screen_resolution': request.headers.get('X-Screen-Resolution', ''),\n"
                        "            'timezone': request.headers.get('X-Timezone', '')\n"
                        "        }\n"
                        "        \n"
                        "        # Create hash of fingerprint data\n"
                        "        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)\n"
                        "        return hashlib.sha256(fingerprint_string.encode()).hexdigest()\n\n"
                        "    def is_new_device(self, user_id, device_fingerprint):\n"
                        "        key = f\"user_devices:{user_id}\"\n"
                        "        known_devices = self.redis_client.smembers(key)\n"
                        "        \n"
                        "        return device_fingerprint not in known_devices\n\n"
                        "    def register_device(self, user_id, device_fingerprint, device_info):\n"
                        "        key = f\"user_devices:{user_id}\"\n"
                        "        self.redis_client.sadd(key, device_fingerprint)\n"
                        "        \n"
                        "        # Store device details\n"
                        "        device_key = f\"device_details:{user_id}:{device_fingerprint}\"\n"
                        "        device_data = {\n"
                        "            'fingerprint': device_fingerprint,\n"
                        "            'user_agent': device_info.get('user_agent'),\n"
                        "            'ip_address': device_info.get('ip_address'),\n"
                        "            'first_seen': datetime.utcnow().isoformat(),\n"
                        "            'last_seen': datetime.utcnow().isoformat(),\n"
                        "            'location': device_info.get('location', 'Unknown')\n"
                        "        }\n"
                        "        \n"
                        "        self.redis_client.setex(device_key, 86400 * 365, json.dumps(device_data))\n\n"
                        "    def send_new_device_notification(self, user_email, device_info):\n"
                        "        subject = \"New Device Login Detected\"\n"
                        "        \n"
                        "        body = f\"\"\"\n"
                        "        Hello,\n\n"
                        "        We detected a login to your account from a new device:\n\n"
                        "        Device Information:\n"
                        "        - User Agent: {device_info.get('user_agent', 'Unknown')}\n"
                        "        - IP Address: {device_info.get('ip_address', 'Unknown')}\n"
                        "        - Location: {device_info.get('location', 'Unknown')}\n"
                        "        - Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                        "        If this was you, you can safely ignore this email.\n"
                        "        If you don't recognize this login, please:\n"
                        "        1. Change your password immediately\n"
                        "        2. Enable two-factor authentication\n"
                        "        3. Contact support if needed\n\n"
                        "        Best regards,\n"
                        "        Your Security Team\n"
                        "        \"\"\"\n"
                        "        \n"
                        "        # Send email (implement your email sending logic)\n"
                        "        self._send_email(user_email, subject, body)\n\n"
                        "    def _send_email(self, to_email, subject, body):\n"
                        "        # Implement email sending logic\n"
                        "        # This is a placeholder - implement with your email service\n"
                        "        pass\n\n"
                        "# Usage in login endpoint\n"
                        "'''\n"
                        "device_manager = DeviceManager()\n"
                        "\n"
                        "@app.route('/api/login', methods=['POST'])\n"
                        "def login():\n"
                        "    # ... authentication logic ...\n"
                        "    \n"
                        "    if user_authenticated:\n"
                        "        device_fingerprint = device_manager.generate_device_fingerprint(request)\n"
                        "        \n"
                        "        if device_manager.is_new_device(user_id, device_fingerprint):\n"
                        "            # Send notification\n"
                        "            device_info = {\n"
                        "                'user_agent': request.headers.get('User-Agent'),\n"
                        "                'ip_address': request.remote_addr,\n"
                        "                'location': get_location_from_ip(request.remote_addr)\n"
                        "            }\n"
                        "            device_manager.send_new_device_notification(user.email, device_info)\n"
                        "            \n"
                        "            # Register the new device\n"
                        "            device_manager.register_device(user_id, device_fingerprint, device_info)\n"
                        "        else:\n"
                        "            # Update last seen time\n"
                        "            device_manager.update_device_last_seen(user_id, device_fingerprint)\n"
                        "    \n"
                        "    return jsonify({'success': True})\n"
                        "'''"
                    ],
                    priority=ImplementationPriority.LOW,
                    effort=ImplementationEffort.MEDIUM,
                    estimated_time="3-4 days",
                    dependencies=["Email service", "Redis server", "IP geolocation service"],
                    testing_requirements=[
                        "Test device fingerprinting accuracy",
                        "Verify notification delivery",
                        "Test device registration",
                        "Test device blocking functionality"
                    ],
                    monitoring_requirements=[
                        "Monitor new device notifications",
                        "Track device registration rates",
                        "Alert on suspicious device patterns",
                        "Monitor email delivery success"
                    ]
                )
            ]
        }
        
        return countermeasures
    
    def get_countermeasures_for_threat(self, threat_id: str) -> List[Countermeasure]:
        """Get all countermeasures for a specific threat."""
        return self.countermeasures.get(threat_id, [])
    
    def get_all_countermeasures(self) -> Dict[str, List[Countermeasure]]:
        """Get all countermeasures organized by threat."""
        return self.countermeasures
    
    def generate_countermeasures_report(self) -> Dict[str, Any]:
        """Generate a comprehensive countermeasures report."""
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_threats": len(self.countermeasures),
                "total_countermeasures": sum(len(cms) for cms in self.countermeasures.values()),
                "report_type": "Threat Countermeasures and Solutions Report"
            },
            "summary": {
                "critical_priority": 0,
                "high_priority": 0,
                "medium_priority": 0,
                "low_priority": 0,
                "easy_effort": 0,
                "medium_effort": 0,
                "hard_effort": 0
            },
            "threat_countermeasures": {}
        }
        
        # Process each threat and its countermeasures
        for threat_id, countermeasures in self.countermeasures.items():
            threat_data = {
                "threat_id": threat_id,
                "countermeasures": []
            }
            
            for cm in countermeasures:
                # Update summary counts
                if cm.priority == ImplementationPriority.CRITICAL:
                    report["summary"]["critical_priority"] += 1
                elif cm.priority == ImplementationPriority.HIGH:
                    report["summary"]["high_priority"] += 1
                elif cm.priority == ImplementationPriority.MEDIUM:
                    report["summary"]["medium_priority"] += 1
                elif cm.priority == ImplementationPriority.LOW:
                    report["summary"]["low_priority"] += 1
                
                if cm.effort == ImplementationEffort.EASY:
                    report["summary"]["easy_effort"] += 1
                elif cm.effort == ImplementationEffort.MEDIUM:
                    report["summary"]["medium_effort"] += 1
                elif cm.effort == ImplementationEffort.HARD:
                    report["summary"]["hard_effort"] += 1
                
                threat_data["countermeasures"].append(asdict(cm))
            
            report["threat_countermeasures"][threat_id] = threat_data
        
        return report
    
    def export_countermeasures_to_json(self, filename: str = None) -> str:
        """Export countermeasures report to JSON file."""
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"countermeasures_report_{timestamp}.json"
        
        report = self.generate_countermeasures_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename


def main():
    """Main function to demonstrate countermeasures functionality."""
    countermeasures = ThreatCountermeasures()
    
    # Generate and export report
    filename = countermeasures.export_countermeasures_to_json()
    print(f"Countermeasures report generated: {filename}")
    
    # Print summary
    report = countermeasures.generate_countermeasures_report()
    summary = report["summary"]
    
    print("\n=== Countermeasures Summary ===")
    print(f"Total Countermeasures: {report['report_metadata']['total_countermeasures']}")
    print(f"Critical Priority: {summary['critical_priority']}")
    print(f"High Priority: {summary['high_priority']}")
    print(f"Medium Priority: {summary['medium_priority']}")
    print(f"Low Priority: {summary['low_priority']}")
    print(f"Easy Effort: {summary['easy_effort']}")
    print(f"Medium Effort: {summary['medium_effort']}")
    print(f"Hard Effort: {summary['hard_effort']}")
    
    # Print threat-specific countermeasures
    print("\n=== Threat Countermeasures ===")
    for threat_id, data in report["threat_countermeasures"].items():
        print(f"\nThreat {threat_id}:")
        for cm in data["countermeasures"]:
            print(f"  - {cm['title']} ({cm['priority']} priority, {cm['effort']} effort)")


if __name__ == "__main__":
    main() 