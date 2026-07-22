using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's domain events. Payloads carry ids and coarse metadata
/// only - never a secret. These are tenant-scoped events: OutboxWriter stamps
/// tenant_id from the tenant the enqueue runs under (the provisioner's context
/// is resolved to the new tenant), so each row lands with tenant_id = the new
/// tenant without the module setting it.
/// </summary>
internal static class TenancyEvents
{
    private const string Module = "tenancy";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// tenancy.tenant.created: a new tenant boundary was established. Actor is
    /// the creating user (the first owner). No payload beyond that by design.
    /// </summary>
    public static DomainEventRecord TenantCreated(Guid tenantId, Guid createdBy, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "tenancy.tenant.created",
        EntityId = tenantId,
        ActorUserId = createdBy,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    /// <summary>
    /// tenancy.membership.created: a user joined a tenant with a role. Carries
    /// the coarse role only - never any credential or contact detail.
    /// </summary>
    public static DomainEventRecord MembershipCreated(
        Guid membershipId,
        Guid tenantId,
        Guid userId,
        string role,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "tenancy.membership.created",
            EntityId = membershipId,
            ActorUserId = userId,
            Payload = JsonSerializer.Serialize(new { role }, Json),
        };
}
