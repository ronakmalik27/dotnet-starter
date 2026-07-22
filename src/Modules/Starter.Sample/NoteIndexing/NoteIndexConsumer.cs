using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Starter.Sample.Domain;
using Starter.Platform.Events;
using Starter.Platform.Tenancy;
using Starter.SharedKernel;

namespace Starter.Sample.NoteIndexing;

/// <summary>
/// The Sample module's tenant-scoped consumer: on sample.note.created it
/// maintains sample.note_index, a per-tenant read model. It is the worked
/// example of a first-class, tenant-bound consumer.
/// <para>
/// The dispatcher binds this scope's tenant from the event's tenant_id before
/// this runs, so both the read of the note and the write of the projection are
/// bound by row-level security to that one tenant: the consumer can only ever
/// see and write its own tenant's rows, even though it never filters by tenant
/// itself. The effect is an idempotent upsert keyed by the note id, so a
/// redelivery (at-least-once) just re-writes the same row - no dedup ledger
/// needed. Fast lane: the work is in-process DB, no provider call.
/// </para>
/// </summary>
internal sealed class NoteIndexConsumer : IDomainEventConsumer
{
    public Lane Lane => Lane.Fast;

    public IReadOnlyCollection<string> EventTypes { get; } = ["sample.note.created"];

    public async Task ConsumeAsync(
        IServiceProvider services,
        DomainEventRecord domainEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(domainEvent);

        var db = services.GetRequiredService<SampleDbContext>();
        var tenant = services.GetRequiredService<ITenantContext>();
        var clock = services.GetRequiredService<Clock>();

        // The transaction is what makes the interceptor set the tenant GUC, so
        // everything below runs under RLS for the event's tenant.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Read the note the event is about, bound by RLS to this tenant. A note
        // that is not visible (deleted, or another tenant's) reads as null and
        // we stop - there is nothing to project.
        var note = await db.Notes
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == domainEvent.EntityId, cancellationToken);
        if (note is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return;
        }

        // A deliberately broad read: how many notes are visible to this tenant.
        // Under RLS this counts only the event's tenant, which is exactly what
        // the isolation test asserts.
        var visibleNoteCount = await db.Notes.CountAsync(cancellationToken);

        var existing = await db.NoteIndex
            .SingleOrDefaultAsync(row => row.NoteId == note.Id, cancellationToken);
        if (existing is null)
        {
            db.NoteIndex.Add(new NoteIndex
            {
                NoteId = note.Id,
                // Stamped from the tenant context, never from the payload. RLS's
                // WITH CHECK rejects the write if it disagrees with the GUC.
                TenantId = tenant.TenantId,
                TitleLength = note.Title.Length,
                VisibleNoteCount = visibleNoteCount,
                IndexedAt = clock.UtcNow,
            });
        }
        else
        {
            existing.TitleLength = note.Title.Length;
            existing.VisibleNoteCount = visibleNoteCount;
            existing.IndexedAt = clock.UtcNow;
        }

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }
}
