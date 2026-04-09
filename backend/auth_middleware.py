"""
JWT Middleware for Aegis Prime Auditor - Enterprise Auth Layer
Handles: JWT validation, org_id extraction, RBAC, API key auth, session management
"""

import os
import json
import hmac
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple, List
from functools import wraps

import jwt
from fastapi import HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthCredential

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60
REFRESH_TOKEN_EXPIRATION_DAYS = 7

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET not set in environment")

security = HTTPBearer()

# ============================================================================
# DATA MODELS
# ============================================================================

class TokenPayload:
    """JWT token payload structure"""
    def __init__(self, sub: str, org_id: str, role: str, permissions: List[str],
                 sso_provider: Optional[str] = None, groups: Optional[List[str]] = None):
        self.sub = sub  # user UUID
        self.org_id = org_id  # organization UUID
        self.role = role  # admin | editor | viewer
        self.permissions = permissions  # ['scan:create', 'findings:read', ...]
        self.sso_provider = sso_provider  # 'okta' | 'azure_ad' | None
        self.groups = groups or []  # AAD/Okta groups for audit
        self.iat = datetime.now(timezone.utc)
        self.exp = self.iat + timedelta(minutes=JWT_EXPIRATION_MINUTES)

    def to_dict(self) -> Dict:
        return {
            'sub': self.sub,
            'org_id': self.org_id,
            'role': self.role,
            'permissions': self.permissions,
            'sso_provider': self.sso_provider,
            'groups': self.groups,
            'iat': int(self.iat.timestamp()),
            'exp': int(self.exp.timestamp()),
        }

class AuthContext:
    """Authentication context for requests"""
    def __init__(self, user_id: str, org_id: str, role: str, permissions: List[str]):
        self.user_id = user_id
        self.org_id = org_id
        self.role = role
        self.permissions = permissions

    def has_permission(self, permission: str) -> bool:
        """Check if user has permission (e.g., 'scan:create', 'findings:read')"""
        # admin role has all permissions
        if self.role == 'admin':
            return True
        return permission in self.permissions

    def is_admin(self) -> bool:
        return self.role == 'admin'

# ============================================================================
# JWT TOKEN GENERATION & VALIDATION
# ============================================================================

def generate_jwt_token(payload: TokenPayload) -> str:
    """Generate signed JWT token"""
    encoded = jwt.encode(
        payload.to_dict(),
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    return encoded

def generate_refresh_token() -> str:
    """Generate refresh token (random UUID)"""
    return str(uuid.uuid4())

def verify_jwt_token(token: str) -> TokenPayload:
    """Verify JWT token signature and expiration"""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )
        return TokenPayload(
            sub=payload['sub'],
            org_id=payload['org_id'],
            role=payload['role'],
            permissions=payload.get('permissions', []),
            sso_provider=payload.get('sso_provider'),
            groups=payload.get('groups', [])
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

# ============================================================================
# API KEY AUTHENTICATION (CI/CD)
# ============================================================================

def hash_api_key(key: str) -> str:
    """Hash API key for storage (SHA-256)"""
    return hashlib.sha256(key.encode()).hexdigest()

def validate_api_key(key_preview: str, key_hash: str, org_id: str, supabase_client) -> Tuple[bool, Optional[str]]:
    """
    Validate API key against database
    Returns: (is_valid, error_message)
    """
    try:
        result = supabase_client.table('api_keys').select('*').eq(
            'key_preview', key_preview
        ).eq('org_id', org_id).execute()

        if not result.data:
            return False, "API key not found"

        key_record = result.data[0]

        # Check expiration
        if key_record.get('expires_at'):
            if datetime.fromisoformat(key_record['expires_at']) < datetime.now(timezone.utc):
                return False, "API key expired"

        # Verify hash matches
        if key_record['key_hash'] != key_hash:
            return False, "Invalid API key"

        # Check rate limit (basic check)
        # In production, use Redis for distributed rate limiting

        return True, None
    except Exception as e:
        return False, f"API key validation error: {str(e)}"

# ============================================================================
# DEPENDENCY INJECTION FOR FASTAPI
# ============================================================================

async def get_auth_context(request: Request, credentials: HTTPAuthCredential = Depends(security)) -> AuthContext:
    """
    FastAPI dependency to extract and validate JWT from Authorization header

    Usage:
        @app.post("/api/scans")
        async def create_scan(auth: AuthContext = Depends(get_auth_context)):
            print(f"User {auth.user_id} from org {auth.org_id}")
    """
    token = credentials.credentials
    payload = verify_jwt_token(token)
    return AuthContext(
        user_id=payload.sub,
        org_id=payload.org_id,
        role=payload.role,
        permissions=payload.permissions
    )

async def get_auth_context_optional(request: Request) -> Optional[AuthContext]:
    """Optional auth context (allows unauthenticated access with fallback)"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None

    token = auth_header.replace('Bearer ', '')
    try:
        payload = verify_jwt_token(token)
        return AuthContext(
            user_id=payload.sub,
            org_id=payload.org_id,
            role=payload.role,
            permissions=payload.permissions
        )
    except HTTPException:
        return None

# ============================================================================
# PERMISSION DECORATORS
# ============================================================================

def require_permission(permission: str):
    """Decorator to check if user has specific permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, auth: AuthContext = Depends(get_auth_context), **kwargs):
            if not auth.has_permission(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission} required"
                )
            return await func(*args, auth=auth, **kwargs)
        return wrapper
    return decorator

def require_admin():
    """Decorator to check if user is admin"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, auth: AuthContext = Depends(get_auth_context), **kwargs):
            if not auth.is_admin():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin access required"
                )
            return await func(*args, auth=auth, **kwargs)
        return wrapper
    return decorator

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

class SessionManager:
    """Manages user sessions with expiration and revocation"""

    def __init__(self, supabase_client):
        self.supabase = supabase_client

    def create_session(self, user_id: str, org_id: str, ip_address: str, user_agent: str) -> Dict:
        """Create new session"""
        session_id = str(uuid.uuid4())
        access_token_hash = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        refresh_token_hash = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        session_data = {
            'id': session_id,
            'user_id': user_id,
            'org_id': org_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'access_token_hash': access_token_hash,
            'refresh_token_hash': refresh_token_hash,
            'expires_at': expires_at,
        }

        self.supabase.table('sessions').insert(session_data).execute()

        return {
            'session_id': session_id,
            'access_token': access_token_hash,
            'refresh_token': refresh_token_hash,
            'expires_at': expires_at
        }

    def validate_session(self, session_id: str, user_id: str) -> bool:
        """Validate session is active and not expired"""
        try:
            result = self.supabase.table('sessions').select('*').eq(
                'id', session_id
            ).eq('user_id', user_id).eq('revoked_at', None).execute()

            if not result.data:
                return False

            session = result.data[0]
            expires_at = datetime.fromisoformat(session['expires_at'])

            return expires_at > datetime.now(timezone.utc)
        except:
            return False

    def revoke_session(self, session_id: str):
        """Revoke session (logout)"""
        self.supabase.table('sessions').update({
            'revoked_at': datetime.now(timezone.utc).isoformat()
        }).eq('id', session_id).execute()

# ============================================================================
# ROLE-BASED ACCESS CONTROL (RBAC)
# ============================================================================

ROLE_PERMISSIONS = {
    'admin': [
        'scan:create', 'scan:read', 'scan:update', 'scan:delete',
        'findings:suppress', 'findings:export',
        'compliance:manage', 'compliance:export',
        'user:create', 'user:delete', 'user:update',
        'billing:view', 'billing:update',
        'org:settings:update', 'org:api_keys:manage',
        'audit_log:read', 'audit_log:export'
    ],
    'editor': [
        'scan:create', 'scan:read', 'scan:update',
        'findings:suppress',
        'compliance:check',
        'project:update',
        'audit_log:read'
    ],
    'viewer': [
        'scan:read',
        'findings:read',
        'compliance:read',
        'audit_log:read',
        'project:read'
    ]
}

def get_role_permissions(role: str) -> List[str]:
    """Get list of permissions for role"""
    return ROLE_PERMISSIONS.get(role, [])

# ============================================================================
# SSO / SAML HANDLING (Phase 2 - Sprint 9)
# ============================================================================

class SSOHandler:
    """Handle SSO provider integrations (Okta, Azure AD, Google)"""

    def __init__(self, supabase_client):
        self.supabase = supabase_client

    def validate_saml_assertion(self, provider: str, assertion: str) -> Optional[Dict]:
        """
        Validate SAML assertion from SSO provider
        Returns user data if valid, None otherwise

        Real implementation would use python3-saml library
        """
        # Placeholder: In production, use saml2 library
        # 1. Verify XML signature
        # 2. Check assertion audience
        # 3. Extract NameID and attributes
        # 4. Map attributes to org/role
        pass

    def jit_provision_user(self, org_id: str, email: str, full_name: str,
                          groups: List[str], sso_provider: str) -> str:
        """
        Just-In-Time provision user if doesn't exist
        Map group names to roles
        Returns user_id
        """
        # 1. Check if user exists
        result = self.supabase.table('users').select('id').eq(
            'org_id', org_id
        ).eq('email', email).execute()

        if result.data:
            return result.data[0]['id']

        # 2. Map groups to role
        role = self._map_groups_to_role(groups, sso_provider)

        # 3. Create user
        user_data = {
            'org_id': org_id,
            'email': email,
            'full_name_encrypted': full_name,  # In production, encrypt this
            'role': role,
            'mfa_enabled': False
        }

        result = self.supabase.table('users').insert(user_data).execute()
        return result.data[0]['id']

    def _map_groups_to_role(self, groups: List[str], sso_provider: str) -> str:
        """Map SSO provider groups to application roles"""
        # Example mapping:
        # Okta group "developers" -> editor
        # Okta group "security-team" -> admin
        # Default -> viewer

        group_mapping = {
            'developers': 'editor',
            'security-team': 'admin',
            'finance': 'viewer',
        }

        for group in groups:
            if group.lower() in group_mapping:
                return group_mapping[group.lower()]

        return 'viewer'  # Default role
