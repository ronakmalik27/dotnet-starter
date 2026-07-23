using Microsoft.EntityFrameworkCore;
using Starter.Platform.Dsar;

namespace Starter.Tenancy.Dsar;

/// <summary>
/// The Tenancy module's export contributors (data-export-and-erasure.md section 3):
/// the tenant profile, memberships, workspaces, teams and their members, custom roles
/// and their permissions, role assignments, invitations, and service accounts (with
/// <c>key_hash</c> EXCLUDED, section 8). Each reads the request-scoped, RLS-bound
/// <see cref="TenancyDbContext"/> inside a transaction (the interceptor sets the tenant
/// GUC on transaction start), so a contributor only ever sees the ACTIVE tenant's rows.
/// NO bypass anywhere - export is a self-serve read of the caller's own tenant.
/// </summary>
internal static class TenancyExportContributors
{
    /// <summary>The tenant profile row (a single object, not a collection).</summary>
    internal sealed class TenantProfile(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "tenant";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var tenant = await db.Tenants
                .AsNoTracking()
                .Select(row => new
                {
                    row.Id,
                    row.Slug,
                    row.Name,
                    row.Status,
                    row.Plan,
                    row.SeatLimit,
                    row.CreatedAt,
                    row.CreatedBy,
                    row.DeletedAt,
                })
                .SingleOrDefaultAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return tenant;
        }
    }

    /// <summary>The tenant's memberships (roster).</summary>
    internal sealed class Memberships(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "memberships";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.Memberships
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.UserId,
                    row.Role,
                    row.Status,
                    row.InvitedBy,
                    // The IdP's SCIM externalId (personal data, not a secret): it
                    // belongs in an Art. 15 export like the rest of the row.
                    row.ScimExternalId,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's workspaces.</summary>
    internal sealed class Workspaces(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "workspaces";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.Workspaces
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Slug,
                    row.Name,
                    row.Status,
                    row.CreatedBy,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's teams.</summary>
    internal sealed class Teams(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "teams";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.Teams
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Slug,
                    row.Name,
                    row.CreatedBy,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's team memberships.</summary>
    internal sealed class TeamMembers(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "teamMembers";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.TeamMembers
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.TeamId,
                    row.UserId,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's custom roles.</summary>
    internal sealed class Roles(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "roles";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.Roles
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Key,
                    row.Name,
                    row.Description,
                    row.AssignableAt,
                    row.WorkspaceId,
                    row.CreatedBy,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The custom roles' permissions.</summary>
    internal sealed class RolePermissions(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "rolePermissions";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.RolePermissions
                .AsNoTracking()
                .OrderBy(row => row.RoleId)
                .ThenBy(row => row.Permission)
                .Select(row => new
                {
                    row.RoleId,
                    row.Permission,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's role assignments (grants).</summary>
    internal sealed class RoleAssignments(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "roleAssignments";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.RoleAssignments
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.RoleId,
                    row.PrincipalType,
                    row.PrincipalId,
                    row.ScopeType,
                    row.ScopeId,
                    row.GrantedBy,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's invitations. The token HASH is EXCLUDED (a credential artifact, section 8).</summary>
    internal sealed class Invitations(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "invitations";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.Invitations
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Email,
                    row.Role,
                    row.ExpiresAt,
                    row.AcceptedAt,
                    row.WorkspaceId,
                    row.RoleId,
                    row.InvitedBy,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's SSO configuration. The <c>client_secret_encrypted</c> is EXCLUDED (a credential column, section 8).</summary>
    internal sealed class SsoConfiguration(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "ssoConfig";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var config = await db.SsoConfigs
                .AsNoTracking()
                .Select(row => new
                {
                    row.Issuer,
                    row.ClientId,
                    // ClientSecretEncrypted is deliberately absent (a [Sensitive] credential column).
                    row.Enabled,
                    row.CreatedAt,
                    row.UpdatedAt,
                })
                .SingleOrDefaultAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return config;
        }
    }

    /// <summary>The tenant's SSO routing-domain claims.</summary>
    internal sealed class SsoDomainClaims(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "ssoDomainClaims";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.SsoDomainClaims
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Domain,
                    row.VerifiedAt,
                    row.CreatedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's SCIM tokens. The <c>token_hash</c> is EXCLUDED (a credential column, section 8).</summary>
    internal sealed class ScimTokens(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "scimTokens";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.ScimTokens
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    // TokenHash is deliberately absent (a [Sensitive] credential column).
                    row.TokenPrefix,
                    row.CreatedBy,
                    row.CreatedAt,
                    row.ExpiresAt,
                    row.RevokedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }

    /// <summary>The tenant's service accounts. The <c>key_hash</c> is EXCLUDED (a credential column, section 8).</summary>
    internal sealed class ServiceAccounts(TenancyDbContext db) : IDataExportContributor
    {
        public string Section => "serviceAccounts";

        public async Task<object?> ExportAsync(CancellationToken cancellationToken)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            var rows = await db.ServiceAccounts
                .AsNoTracking()
                .OrderBy(row => row.CreatedAt)
                .ThenBy(row => row.Id)
                .Select(row => new
                {
                    row.Id,
                    row.Name,
                    // KeyHash is deliberately absent (a [Sensitive] credential column).
                    row.KeyPrefix,
                    row.CreatedBy,
                    row.CreatedAt,
                    row.LastUsedAt,
                    row.ExpiresAt,
                    row.RevokedAt,
                })
                .ToListAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return rows;
        }
    }
}
