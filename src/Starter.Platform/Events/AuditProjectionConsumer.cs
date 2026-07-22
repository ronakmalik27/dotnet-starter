using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Platform.Events;

/// <summary>
/// The audit-log projection (audit-log.md sections 2, 3, 5): a Fast-lane,
/// tenant-scoped consumer that projects every tenant-scoped domain event into
/// <c>platform.audit_log</c>, the queryable per-tenant audit trail. It is a
/// Platform consumer (registered in the platform composition), so it references
/// no module: the payload is read by UNTYPED JSON traversal, never a typed module
/// record (the dependency-shape arch test forbids Platform seeing a module type).
/// <para>
/// The dispatcher binds this scope's tenant from the event's tenant_id before this
/// runs, so the insert is bound by row-level security to exactly that tenant - the
/// consumer never filters by tenant itself, and even a bug could not cross
/// tenants. It resolves the request-style (RLS-bound) <see cref="PlatformDbContext"/>
/// from the passed scope, never the bypass data source: Platform owns the bypass
/// mechanism and is not constrained by the containment arch test, so this
/// abstention is deliberate code-review discipline.
/// </para>
/// <para>
/// Dedup is by construction, not by a separate claim: the primary key is the
/// source event id, so a redelivery (at-least-once) hits the pk and is caught as a
/// unique violation the consumer treats as success (the row is already there). A
/// <see cref="ProcessedEventStore"/>-style best-effort claim is deliberately the
/// wrong tool for an audit write, because a claim that commits separately from the
/// write can drop the record.
/// </para>
/// </summary>
internal sealed class AuditProjectionConsumer : IDomainEventConsumer
{
    public Lane Lane => Lane.Fast;

    /// <summary>
    /// The tenant-scoped catalogue this projection subscribes to (audit-log.md
    /// section 2): every event that carries a tenant_id. That is all
    /// <c>tenancy.*</c> control-plane events, the tenant-scoped
    /// <c>platform.impersonation.*</c> events (they carry the target tenant), and
    /// the sample module's <c>sample.note.*</c>. The null-tenant
    /// <c>platform.admin.*</c> events are audited synchronously (section 2) and the
    /// identity user-activity events are deliberately not audited here (section 2);
    /// the catalogue-completeness test enforces that every event type is either
    /// here or in the named not-audited set.
    /// </summary>
    public IReadOnlyCollection<string> EventTypes { get; } =
    [
        // tenancy.* control plane
        "tenancy.tenant.created",
        "tenancy.membership.created",
        "tenancy.member.role_changed",
        "tenancy.member.removed",
        "tenancy.invitation.created",
        "tenancy.invitation.revoked",
        "tenancy.tenant.settings_updated",
        "tenancy.ownership.transferred",
        "tenancy.tenant.soft_deleted",
        "tenancy.tenant.suspended",
        "tenancy.tenant.reactivated",
        "tenancy.workspace.created",
        "tenancy.workspace.renamed",
        "tenancy.workspace.archived",
        "tenancy.workspace.unarchived",
        "tenancy.role.created",
        "tenancy.role.updated",
        "tenancy.role.deleted",
        "tenancy.role_assignment.granted",
        "tenancy.role_assignment.revoked",
        "tenancy.team.created",
        "tenancy.team.renamed",
        "tenancy.team.deleted",
        "tenancy.team.member_added",
        "tenancy.team.member_removed",
        // tenant-scoped platform events (carry the target tenant)
        "platform.impersonation.started",
        "platform.impersonation.ended",
        // sample module
        "sample.note.created",
    ];

    public async Task ConsumeAsync(
        IServiceProvider services,
        DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(domainEvent);

        var db = services.GetRequiredService<PlatformDbContext>();
        var tenant = services.GetRequiredService<ITenantContext>();
        var clock = services.GetRequiredService<Clock>();

        // The transaction is what makes the interceptor set the tenant GUC, so
        // the insert below runs under RLS for the event's tenant.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        db.AuditLog.Add(new AuditLogRow
        {
            Id = domainEvent.Id,
            // Stamped from the tenant context, never from the payload. RLS's
            // WITH CHECK rejects the write if it disagrees with the GUC.
            TenantId = tenant.TenantId,
            OccurredAt = domainEvent.OccurredAt,
            RecordedAt = clock.UtcNow,
            Action = domainEvent.EventType,
            ActorUserId = domainEvent.ActorUserId,
            EntityId = domainEvent.EntityId,
            Summary = AuditSummary.Render(domainEvent),
            Data = domainEvent.Payload,
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // At-least-once redelivery: the row already exists (pk = event id).
            // The failed insert aborted this transaction; roll back the empty
            // unit and treat the redelivery as success (idempotent by
            // construction).
            await transaction.RollbackAsync(cancellationToken);
            return;
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
