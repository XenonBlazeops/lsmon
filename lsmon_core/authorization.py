from .models import Membership

class AuthorizationDenied(PermissionError):
    pass


def is_global_admin(user):
    return user.is_authenticated and Membership.objects.filter(
        user=user, tenant__isnull=True, role=Membership.Role.GLOBAL_ADMIN
    ).exists()

def require_tenant_role(user, tenant_id, allowed_roles):
    if is_global_admin(user):
        return None
    membership = Membership.objects.filter(
        tenant_id=tenant_id, user=user, tenant__active=True, role__in=allowed_roles
    ).first()
    if membership is None:
        raise AuthorizationDenied("Tenant-scoped access denied")
    return membership

def require_asset_access(user, asset, allowed_roles):
    return require_tenant_role(user, asset.tenant_id, allowed_roles)

def visible_tenants(user):
    from .models import Tenant
    if is_global_admin(user):
        return Tenant.objects.filter(active=True)
    return Tenant.objects.filter(
        active=True, membership__user=user
    ).distinct()

def can_view_operations(user):
    return Membership.objects.filter(
        user=user,
        role__in=(Membership.Role.GLOBAL_ADMIN, Membership.Role.NOC_SOC),
    ).exists()
