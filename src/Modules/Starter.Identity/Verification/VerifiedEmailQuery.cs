using Microsoft.EntityFrameworkCore;

namespace Starter.Identity.Verification;

/// <summary>
/// The `vrf` gate's question (doc 10 section 5): is this account's email
/// verified? One indexed primary-key read; a missing or deleted row is
/// simply "not verified" - the gate fails closed either way. Deliberately
/// bool-only: the gate needs nothing else, and the invited-vs-organic
/// write-lock derivation (deadline-aware) joins with the endpoints it
/// gates (Trips HTTP wave).
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
