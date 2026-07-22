using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;

namespace Starter.Identity.Tokens;

/// <summary>
/// The read side of the platform's IUserDirectory seam: minimal, read-only
/// lookups other modules need without referencing Identity. Users are global (no
/// tenant, no RLS), so these are plain indexed reads on the request connection -
/// email is a unique citext column, so the by-email lookup is case-insensitive
/// and at most one row. Both restrict to active accounts: a missing or inactive
/// row is simply "no such user".
/// </summary>
internal sealed class UserDirectoryQuery(IdentityDbContext db)
{
    public Task<string?> GetEmailAsync(Guid userId, CancellationToken cancellationToken) =>
        db.Users
            .AsNoTracking()
            .Where(user => user.Id == userId && user.Status == UserStatus.Active)
            .Select(user => (string?)user.Email)
            .SingleOrDefaultAsync(cancellationToken);

    public async Task<Guid?> FindUserIdByEmailAsync(string email, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);

        var id = await db.Users
            .AsNoTracking()
            .Where(user => user.Email == email && user.Status == UserStatus.Active)
            .Select(user => (Guid?)user.Id)
            .SingleOrDefaultAsync(cancellationToken);
        return id;
    }
}
