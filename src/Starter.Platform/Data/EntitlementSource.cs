using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Starter.Platform.Auth;

namespace Starter.Platform.Data;

/// <summary>
/// The default <see cref="IEntitlementSource"/> (billing-and-entitlements.md
/// section 3): a per-resolve read of the <c>platform.plans</c> catalogue through
/// the request-scoped <see cref="PlatformDbContext"/>. The catalogue is a no-RLS
/// platform table, so this needs no bypass data source and no tenant GUC - it is
/// request/consumer code by placement, and its abstention from the bypass source
/// is the whole point of putting the resolve here rather than in the control
/// plane.
/// <para>
/// Fail-open by construction: a null, blank, or unknown plan key resolves to
/// <see cref="Entitlements.Unrestricted"/>, and a plan whose <c>features</c> /
/// <c>permissions</c> arrays are SQL NULL yields null sets (unrestricted). Only a
/// plan an operator deliberately publishes with a non-null list bites.
/// </para>
/// </summary>
internal sealed class EntitlementSource(PlatformDbContext db) : IEntitlementSource
{
    public async Task<Entitlements> ResolveAsync(string? planKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(planKey))
        {
            // No plan on the tenant: billing is not configured, so nothing is
            // restricted (fail open).
            return Entitlements.Unrestricted;
        }

        var plan = await db.Plans
            .AsNoTracking()
            .SingleOrDefaultAsync(row => row.Key == planKey, cancellationToken);
        if (plan is null)
        {
            // An unknown / dangling plan key: fail open, never lock the tenant out.
            return Entitlements.Unrestricted;
        }

        // A non-null array is CLOSED to exactly that set; SQL NULL is unrestricted
        // (a null set here). This is the inversion that lets the default plan be
        // unrestricted while a paid tier sets explicit lists.
        var features = plan.Features is null
            ? null
            : (IReadOnlySet<string>)plan.Features.ToHashSet(StringComparer.Ordinal);
        var permissions = plan.Permissions is null
            ? null
            : (IReadOnlySet<string>)plan.Permissions.ToHashSet(StringComparer.Ordinal);

        return new Entitlements(features, permissions, ParseLimits(plan.Limits));
    }

    private static Dictionary<string, int> ParseLimits(string limits)
    {
        if (string.IsNullOrWhiteSpace(limits))
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, int>>(limits)
                ?? new Dictionary<string, int>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            // A malformed limits blob should never happen (create/update validate
            // it), but a parse failure must not throw on a request path - treat it
            // as "no declared limits" (the seat check still reads the denormalized
            // tenant.seat_limit column, so seats are unaffected).
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }
    }
}
