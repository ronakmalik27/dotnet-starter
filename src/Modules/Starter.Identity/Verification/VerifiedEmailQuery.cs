using Microsoft.EntityFrameworkCore;

namespace Starter.Identity.Verification;

/// <summary>
/// The `vrf` gate's question: is this account's email
/// verified? One indexed primary-key read; a missing or deleted row is
/// simply "not verified" - the gate fails closed either way. Deliberately
/// bool-only: the gate needs nothing else, and the deadline-aware
/// write-lock derivation joins with the endpoints it
/// gates in a later HTTP wave.
/// </summary>
internal sealed class VerifiedEmailQuery(IdentityDbContext db)
{
    public Task<bool> IsVerifiedAsync(Guid userId, CancellationToken cancellationToken) =>
        db.Users
            .AsNoTracking()
            .AnyAsync(
                candidate => candidate.Id == userId && candidate.EmailVerifiedAt != null,
                cancellationToken);
}
