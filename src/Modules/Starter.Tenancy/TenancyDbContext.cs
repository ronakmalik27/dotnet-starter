using Microsoft.EntityFrameworkCore;
using Starter.Tenancy.Domain;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's context: owns the tenancy schema and nothing else. Both
/// entities are tenant-owned, so each carries the tenant query filter on top of
/// the RLS policy in the database.
/// <para>
/// Memberships filter the ordinary way (a tenant_id column, via
/// ApplyTenantFilter, exactly as Sample does). Tenants are the special case: the
/// tenant's OWN id is the discriminator (no tenant_id column), so the filter
/// keys on id - the RLS policy on tenants keys on id too. The filter reads
/// TenantContext as an instance member, so the singleton-cached compiled model
/// never bakes in one request's tenant.
/// </para>
/// </summary>
internal sealed class TenancyDbContext(DbContextOptions<TenancyDbContext> options, ITenantContext tenantContext)
    : ModuleDbContext(options, SchemaName, tenantContext)
{
    internal const string SchemaName = "tenancy";

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<Membership> Memberships => Set<Membership>();

    public DbSet<Invitation> Invitations => Set<Invitation>();

    public DbSet<Workspace> Workspaces => Set<Workspace>();

    public DbSet<CustomRole> Roles => Set<CustomRole>();

    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    public DbSet<RoleAssignment> RoleAssignments => Set<RoleAssignment>();

    public DbSet<Team> Teams => Set<Team>();

    public DbSet<TeamMember> TeamMembers => Set<TeamMember>();

    public DbSet<ServiceAccount> ServiceAccounts => Set<ServiceAccount>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // citext: case-insensitive slug uniqueness in the column type itself,
        // so "Acme" and "acme" collide and no lookup can forget to normalize.
        modelBuilder.HasPostgresExtension("citext");

        modelBuilder.Entity<Tenant>(tenant =>
        {
            tenant.Property(t => t.Slug).HasColumnType("citext");
            tenant.HasIndex(t => t.Slug).IsUnique();
            tenant.Property(t => t.Status).HasMaxLength(32);
            tenant.Property(t => t.Plan).HasColumnType("text");
            // TenantId is a computed alias for the primary key, not a stored
            // column; ignore it and filter on id directly (the tenant's own id
            // is the discriminator, matching the RLS policy keyed on id).
            tenant.Ignore(t => t.TenantId);
            tenant.HasQueryFilter(t => t.Id == TenantContext.TenantId);
        });

        modelBuilder.Entity<Membership>(membership =>
        {
            membership.Property(m => m.Role).HasMaxLength(32);
            membership.Property(m => m.Status).HasMaxLength(32);
            // A user belongs to a tenant at most once; also the mint-check
            // lookup index (tenant_id, user_id).
            membership.HasIndex(m => new { m.TenantId, m.UserId }).IsUnique();
            ApplyTenantFilter(membership);
        });

        modelBuilder.Entity<Invitation>(invitation =>
        {
            invitation.Property(i => i.Email).HasColumnType("citext");
            invitation.Property(i => i.Role).HasMaxLength(32);
            invitation.Property(i => i.TokenHash).HasMaxLength(64);
            // The accept lookup keys on the hash (a plain index; the accept
            // path reads it on the bypass source before any tenant is bound).
            invitation.HasIndex(i => i.TokenHash);
            // The pending-list and duplicate-invite checks key on (tenant, email).
            invitation.HasIndex(i => new { i.TenantId, i.Email });
            // workspace_id and role_id are nullable scalar columns (the
            // scope-aware invite, section 16), referenced by value only - no
            // navigation, so the accept path can read them by raw SQL on the
            // bypass source. Both are null for a plain tenant invite.
            ApplyTenantFilter(invitation);
        });

        modelBuilder.Entity<Workspace>(workspace =>
        {
            // citext slug, unique per tenant - the same case-insensitive scheme
            // tenancy.tenants uses, so "Prod" and "prod" collide within a tenant
            // and no lookup can forget to normalize.
            workspace.Property(w => w.Slug).HasColumnType("citext");
            workspace.Property(w => w.Status).HasMaxLength(16);
            workspace.HasIndex(w => new { w.TenantId, w.Slug }).IsUnique();
            ApplyTenantFilter(workspace);
        });

        modelBuilder.Entity<CustomRole>(role =>
        {
            role.Property(r => r.Key).HasMaxLength(64);
            role.Property(r => r.AssignableAt).HasMaxLength(16);
            role.Property(r => r.TemplateKey).HasMaxLength(64);
            // A key is unique within its owning scope: the tenant for a
            // tenant-owned role (workspace_id null), the workspace for a
            // workspace-local one. workspace_id is always null this increment;
            // AreNullsDistinct(false) makes two null workspace_ids collide, so
            // two tenant-owned roles cannot share a key (a plain unique index
            // would treat null != null and let duplicates through).
            role.HasIndex(r => new { r.TenantId, r.WorkspaceId, r.Key })
                .IsUnique()
                .AreNullsDistinct(false);
            // The role-template idempotency backstop
            // (role-templates-and-policy-defaults.md section 2): a PARTIAL unique
            // index on (tenant_id, template_key) covering only the seeded rows
            // (template_key IS NOT NULL). A tenant-authored role has template_key
            // null and never contends here, while a concurrent bulk-seed and a
            // concurrent provision cannot double-seed the same template into a
            // tenant. The app-level "skip if already seeded" pre-check is the
            // friendly path; this index is the race guard.
            role.HasIndex(r => new { r.TenantId, r.TemplateKey })
                .IsUnique()
                .HasFilter("template_key is not null")
                .HasDatabaseName("ux_roles_tenant_template_key");
            ApplyTenantFilter(role);
        });

        modelBuilder.Entity<RolePermission>(permission =>
        {
            permission.HasKey(p => new { p.RoleId, p.Permission });
            permission.Property(p => p.Permission).HasMaxLength(64);
            // Intra-schema FK: a custom role's permissions vanish with it
            // (cascade). Cross-tenant is impossible - both ends carry tenant_id
            // under the same RLS policy.
            permission.HasOne<CustomRole>()
                .WithMany()
                .HasForeignKey(p => p.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
            ApplyTenantFilter(permission);
        });

        modelBuilder.Entity<RoleAssignment>(assignment =>
        {
            assignment.Property(a => a.PrincipalType).HasMaxLength(16);
            assignment.Property(a => a.ScopeType).HasMaxLength(16);
            // A role in use cannot be deleted (the service guardrail rejects it;
            // Restrict is the database backstop, so a grant never dangles).
            assignment.HasOne<CustomRole>()
                .WithMany()
                .HasForeignKey(a => a.RoleId)
                .OnDelete(DeleteBehavior.Restrict);
            // Uniqueness is per scope kind: a null scope_id would not collide
            // under a plain unique constraint, so each scope gets its own
            // partial unique index (the tenant-scope one omits scope_id; the
            // workspace-scope one includes it, for the forward-compat increment).
            assignment.HasIndex(a => new { a.TenantId, a.PrincipalType, a.PrincipalId, a.RoleId })
                .IsUnique()
                .HasFilter("scope_type = 'tenant'")
                .HasDatabaseName("ix_role_assignments_tenant_scope_unique");
            assignment.HasIndex(a => new { a.TenantId, a.PrincipalType, a.PrincipalId, a.RoleId, a.ScopeId })
                .IsUnique()
                .HasFilter("scope_type = 'workspace'")
                .HasDatabaseName("ix_role_assignments_workspace_scope_unique");
            ApplyTenantFilter(assignment);
        });

        modelBuilder.Entity<Team>(team =>
        {
            // citext slug, unique per tenant - the same case-insensitive scheme
            // tenancy.tenants and tenancy.workspaces use, so "Core" and "core"
            // collide within a tenant and no lookup can forget to normalize.
            team.Property(t => t.Slug).HasColumnType("citext");
            team.HasIndex(t => new { t.TenantId, t.Slug }).IsUnique();
            ApplyTenantFilter(team);
        });

        modelBuilder.Entity<TeamMember>(member =>
        {
            // A user belongs to a team at most once (team_id, user_id).
            member.HasIndex(m => new { m.TeamId, m.UserId }).IsUnique();
            // Intra-schema FK: a team's memberships vanish with it (cascade).
            // Cross-tenant is impossible - both ends carry tenant_id under the
            // same RLS policy.
            member.HasOne<Team>()
                .WithMany()
                .HasForeignKey(m => m.TeamId)
                .OnDelete(DeleteBehavior.Cascade);
            ApplyTenantFilter(member);
        });

        modelBuilder.Entity<ServiceAccount>(account =>
        {
            account.Property(a => a.Name).HasColumnType("text");
            account.Property(a => a.KeyHash).HasMaxLength(64);
            account.Property(a => a.KeyPrefix).HasMaxLength(32);
            // The key_hash index is GLOBAL and unique (service-accounts.md section
            // 5): the resolve is tenant-less (a request has no tid until the key
            // resolves it), so the lookup keys on the hash alone. RLS governs
            // visibility, not this constraint, so cross-tenant uniqueness is fine.
            account.HasIndex(a => a.KeyHash)
                .IsUnique()
                .HasDatabaseName("ix_service_accounts_key_hash_unique");
            // The admin list is a tenant-scoped read (service-accounts.md section 5).
            account.HasIndex(a => a.TenantId);
            ApplyTenantFilter(account);
        });
    }
}
