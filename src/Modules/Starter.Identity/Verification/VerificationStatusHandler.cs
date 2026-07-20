using Microsoft.EntityFrameworkCore;
using Starter.Identity.Domain;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Verification;

/// <summary>
/// The render-only half of the verification-status split: GET on a tokenized
/// verify-email link reports the token's state and changes NOTHING - a
/// link-scanner prefetch (Outlook SafeLinks class) that opens every URL in
/// an email must never burn the token. Pure read by construction: no
/// transaction, no writes, no side channel.
/// </summary>
internal sealed class VerificationStatusHandler(IdentityDbContext db, Clock clock)
{
    private static readonly Error UnknownToken = new(
        ErrorKind.NotFound,
        "auth.verification_token_unknown",
        "This verification link does not exist.");

    public async Task<Result<VerificationTokenStatus>> HandleAsync(
        string token,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.Length == 0)
        {
            return UnknownToken;
        }

        var tokenHash = OneTimeTokenSecrets.Hash(token);
        var row = await db.OneTimeTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.TokenHash == tokenHash
                    && candidate.Purpose == OneTimeTokenPurpose.VerifyEmail,
                cancellationToken);
        if (row is null)
        {
            return UnknownToken;
        }

        if (row.UsedAt is not null)
        {
            return VerificationTokenStatus.Used;
        }

        return row.ExpiresAt <= clock.UtcNow
            ? VerificationTokenStatus.Expired
            : VerificationTokenStatus.Valid;
    }
}
