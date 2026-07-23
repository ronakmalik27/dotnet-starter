using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity.Passwords;

/// <summary>
/// The password policy: minimum length plus the offline breach check,
/// deliberately no composition rules and no rotation nagging (the NIST SP 800-63B
/// position). The minimum length is the install-wide platform default
/// (role-templates-and-policy-defaults.md section 3), read from
/// <see cref="IPolicyDefaults"/> instead of a const - raising the platform minimum
/// applies to the next register / set / change and never invalidates an existing
/// password. The <see cref="MaximumLength"/> Argon2 CPU-guard is unchanged (a hard
/// safety cap, not policy).
/// </summary>
internal sealed class PasswordPolicy(BreachedPasswordSet breachedPasswords, IPolicyDefaults policyDefaults)
{
    /// <summary>
    /// Kept sane rather than unbounded: Argon2 cost is length-linear, so a
    /// megabyte "password" is a CPU-exhaustion vector, not a credential.
    /// 256 is far above any passphrase and matches common practice
    /// (OWASP recommends capping around 64+; bcrypt shops cap at 72).
    /// </summary>
    internal const int MaximumLength = 256;

    public async Task<Result> CheckAsync(string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);

        var minimumLength = (await policyDefaults.GetAsync(cancellationToken)).PasswordMinLength;
        if (password.Length < minimumLength)
        {
            return Result.Failure(new Error(
                ErrorKind.Validation,
                "auth.password_too_short",
                $"Passwords must be at least {minimumLength} characters."));
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
                "This password appears in known data breaches; choose a different one."));
        }

        return Result.Success();
    }
}
