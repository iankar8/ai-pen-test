# SECURE CODE: Proper Authorization Check
# PATTERN: Validating user ownership before access
# OWASP: A01:2021 - Broken Access Control (MITIGATED)

def get_user_profile_safe(user_id, current_user):
    """Secure against IDOR with authorization check"""
    # Only allow users to access their own profile or admin access
    if current_user.id != user_id and not current_user.is_admin:
        raise PermissionDenied("Not authorized to access this profile")
    
    return database.query("SELECT * FROM users WHERE id = ?", (user_id,))

# This is SAFE because:
# - Verifies user ownership before access
# - Checks admin privileges explicitly
# - Raises exception on unauthorized access
