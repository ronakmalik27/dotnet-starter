using Starter.SharedKernel;

namespace Starter.Identity.Passwords;

/// <summary>
/// The FR-AUTH-01 password policy: length >= 10 plus the offline breach
/// check, deliberately no composition rules and no rotation nagging
/// (doc 10 4.1, the NIST SP 800-63B position).
/// </summary>
internal sealed class PasswordPolicy(BreachedPasswordSet breachedPasswords)
{
    internal const int MinimumLength = 10;

    /// <summary>
    /// Kept sane rather than unbounded: Argon2 cost is length-linear, so a
    /// megabyte "password" is a CPU-exhaustion vector, not a credential.
    /// 256 is far above any passphrase and matches common practice
    /// (OWASP recommends capping around 64+; bcrypt shops cap at 72).
    /// </summary>
    internal const int MaximumLength = 256;

    public Result Check(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length < MinimumLength)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "auth.password_too_short",
                $"Passwords must be at least {MinimumLength} characters (FR-AUTH-01)."));
        }

        if (password.Length > MaximumLength)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "auth.password_too_long",
                $"Passwords are capped at {MaximumLength} characters."));
        }

        if (breachedPasswords.Contains(password))
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "auth.password_breached",
                "This password appears in known data breaches; choose a different one (FR-AUTH-01)."));
        }

        return Result.Success();
    }
}
