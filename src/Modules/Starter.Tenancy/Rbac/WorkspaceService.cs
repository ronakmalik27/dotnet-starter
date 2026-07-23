using Microsoft.EntityFrameworkCore;
using Npgsql;
using Starter.Tenancy.Domain;
using Starter.Platform.Auth;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Tenancy.Rbac;

/// <summary>
/// The workspace control plane (multi-tenancy.md section 12): create, list, get,
/// rename, and archive workspaces, all operating on the ACTIVE tenant on the
/// REQUEST path under row-level security - NOT the bypass path. A workspace is
/// tenant-owned, so every read and write opens a transaction (the tenant
/// interceptor sets the current-tenant GUC, RLS then binds it to the active
/// tenant) and a workspaceId from another tenant is simply invisible.
/// <para>
/// It also backs the platform <see cref="IWorkspaceReader"/> port that the
/// RequireWorkspace gate uses: existence is the same RLS-bound read, so a
/// cross-tenant workspaceId reads as "not found" and the gate answers 404. The
/// endpoint's permission gate runs before any write here.
/// </para>
/// </summary>
internal sealed class WorkspaceService(
    TenancyDbContext db,
    ITenantContext tenant,
    OutboxWriter outbox,
    IEntitlementSource entitlementSource,
    Clock clock) : IWorkspaceReader
{
    public async Task<(bool Exists, bool Archived)> LookupWorkspaceAsync(
        Guid workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        // One RLS-bound read carries both existence and lifecycle state. A
        // cross-tenant or unknown id yields no row (null status), which the gate
        // turns into 404; an archived workspace is read-only, which the mutating
        // gate turns into 409. The module owns the status vocabulary, so it maps
        // to the platform's vocabulary-agnostic bool here.
        var status = await db.Workspaces
            .AsNoTracking()
            .Where(workspace => workspace.Id == workspaceId)
            .Select(workspace => workspace.Status)
            .SingleOrDefaultAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return status is null ? (false, false) : (true, status == WorkspaceStatus.Archived);
    }

    /// <summary>
    /// True when the workspace is visible under the active tenant's RLS (a thin
    /// convenience over <see cref="LookupWorkspaceAsync"/> for the ITenancyApi
    /// existence surface). The gate itself uses the lookup so it also learns the
    /// archived state in the same read.
    /// </summary>
    public async Task<bool> WorkspaceExistsAsync(Guid workspaceId, CancellationToken cancellationToken) =>
        (await LookupWorkspaceAsync(workspaceId, cancellationToken)).Exists;

    public async Task<Result<Guid>> CreateWorkspaceAsync(
        Guid callerUserId, string slug, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(slug);
        ArgumentNullException.ThrowIfNull(name);

        slug = slug.Trim();
        name = name.Trim();

        if (slug.Length == 0 || slug.Length > 64)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.workspace_slug_invalid", "A workspace slug must be 1-64 characters."));
        }

        if (name.Length == 0)
        {
            return Result.Failure<Guid>(new Error(
                ErrorKind.Validation, "tenancy.workspace_name_required", "A workspace name is required."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The slug is unique per tenant (citext); the unique index is the race
        // backstop, this is the friendly pre-check under RLS.
        var duplicate = await db.Workspaces
            .AsNoTracking()
            .AnyAsync(workspace => workspace.Slug == slug, cancellationToken);
        if (duplicate)
        {
            return Result.Failure<Guid>(WorkspaceSlugTaken);
        }

        // The maxWorkspaces resource-count quota (quotas.md section 6). Resolve the
        // active tenant's plan the GetCallerEntitlementsAsync way: read the tenant's
        // plan under RLS (within this create transaction, so the GUC is set), then the
        // no-RLS catalogue resolve. This is a COMMERCIAL gate, so it FAILS OPEN - an
        // absent maxWorkspaces means unlimited and the create proceeds unchanged.
        // Unlike the seat check (a race-proof denormalized column under FOR UPDATE),
        // workspace creation is human-paced, so the count-then-insert here does not
        // take the tenant-row lock (section 6). A limit of 0 is deny-all (intended).
        var planKey = await db.Tenants
            .AsNoTracking()
            .Select(tenantRow => tenantRow.Plan)
            .SingleOrDefaultAsync(cancellationToken);
        var entitlements = await entitlementSource.ResolveAsync(planKey, cancellationToken);
        if (entitlements.Limits.TryGetValue("maxWorkspaces", out var maxWorkspaces))
        {
            var current = await db.Workspaces.AsNoTracking().CountAsync(cancellationToken);
            if (current >= maxWorkspaces)
            {
                return Result.Failure<Guid>(WorkspaceQuotaReached);
            }
        }

        var row = new Workspace
        {
            Id = Ids.NewId(now),
            TenantId = tenant.TenantId,
            Slug = slug,
            Name = name,
            Status = WorkspaceStatus.Active,
            CreatedBy = callerUserId,
            CreatedAt = now,
        };
        db.Workspaces.Add(row);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            return Result.Failure<Guid>(WorkspaceSlugTaken);
        }

        await outbox.EnqueueAsync(
            db, TenancyEvents.WorkspaceCreated(row.Id, slug, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(row.Id);
    }

    public async Task<IReadOnlyList<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        ListWorkspacesAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.Workspaces
            .AsNoTracking()
            .OrderBy(workspace => workspace.CreatedAt)
            .ThenBy(workspace => workspace.Id)
            .Select(workspace => new
            {
                workspace.Id,
                workspace.Slug,
                workspace.Name,
                workspace.Status,
                workspace.CreatedAt,
            })
            .ToListAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return rows
            .Select(row => (row.Id, row.Slug, row.Name, row.Status, row.CreatedAt))
            .ToList();
    }

    public async Task<Result<(Guid Id, string Slug, string Name, string Status, DateTimeOffset CreatedAt)>>
        GetWorkspaceAsync(Guid workspaceId, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var row = await db.Workspaces
            .AsNoTracking()
            .Where(workspace => workspace.Id == workspaceId)
            .Select(workspace => new
            {
                workspace.Id,
                workspace.Slug,
                workspace.Name,
                workspace.Status,
                workspace.CreatedAt,
            })
            .SingleOrDefaultAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        if (row is null)
        {
            return Result.Failure<(Guid, string, string, string, DateTimeOffset)>(WorkspaceNotFound);
        }

        return Result.Success((row.Id, row.Slug, row.Name, row.Status, row.CreatedAt));
    }

    public async Task<Result> RenameWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);
        name = name.Trim();
        if (name.Length == 0)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation, "tenancy.workspace_name_required", "A workspace name is required."));
        }

        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var workspace = await db.Workspaces.SingleOrDefaultAsync(
            candidate => candidate.Id == workspaceId, cancellationToken);
        if (workspace is null)
        {
            return Result.Failure(WorkspaceNotFound);
        }

        workspace.Name = name;
        await db.SaveChangesAsync(cancellationToken);
        await outbox.EnqueueAsync(
            db, TenancyEvents.WorkspaceRenamed(workspaceId, callerUserId, now), cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success();
    }

    public async Task<Result> ArchiveWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var workspace = await db.Workspaces.SingleOrDefaultAsync(
            candidate => candidate.Id == workspaceId, cancellationToken);
        if (workspace is null)
        {
            return Result.Failure(WorkspaceNotFound);
        }

        // Archive is idempotent: an already-archived workspace is a benign
        // success, so a retry never surprises the caller (section 20 - archive is
        // reversible and nothing is destroyed).
        if (workspace.Status == WorkspaceStatus.Active)
        {
            workspace.Status = WorkspaceStatus.Archived;
            await db.SaveChangesAsync(cancellationToken);
            await outbox.EnqueueAsync(
                db, TenancyEvents.WorkspaceArchived(workspaceId, callerUserId, now), cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    public async Task<Result> UnarchiveWorkspaceAsync(
        Guid callerUserId, Guid workspaceId, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var workspace = await db.Workspaces.SingleOrDefaultAsync(
            candidate => candidate.Id == workspaceId, cancellationToken);
        if (workspace is null)
        {
            return Result.Failure(WorkspaceNotFound);
        }

        // Unarchive is idempotent: an already-active workspace is a benign
        // success. This makes "archive is reversible" (section 20) real - the
        // archived state stops conferring writes, and unarchive restores them.
        if (workspace.Status == WorkspaceStatus.Archived)
        {
            workspace.Status = WorkspaceStatus.Active;
            await db.SaveChangesAsync(cancellationToken);
            await outbox.EnqueueAsync(
                db, TenancyEvents.WorkspaceUnarchived(workspaceId, callerUserId, now), cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private static readonly Error WorkspaceNotFound = new(
        ErrorKind.NotFound, "tenancy.workspace_not_found", "No such workspace.");

    private static readonly Error WorkspaceSlugTaken = new(
        ErrorKind.Conflict, "tenancy.workspace_slug_taken", "A workspace with that slug already exists.");

    // Kind is nominal; the Api maps this code to a dedicated 402 resource-quota
    // answer (quotas.md section 6). It is routed through TenancyProblems by code, so
    // it never reaches the generic ErrorKind table. Mirrors permission_not_in_plan.
    private static readonly Error WorkspaceQuotaReached = new(
        ErrorKind.Validation,
        "tenancy.workspace_quota_reached",
        "This tenant is at its plan's workspace limit.");

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
