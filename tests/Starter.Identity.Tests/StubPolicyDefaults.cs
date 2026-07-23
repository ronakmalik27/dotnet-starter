using Starter.Platform.Auth;

namespace Starter.Identity.Tests;

/// <summary>
/// A fixed-value <see cref="IPolicyDefaults"/> for the identity unit tests: returns
/// the values it is constructed with (defaulting to the built-in constants), so a
/// test can pin the password minimum or the access-token lifetime without a database.
/// </summary>
internal sealed class StubPolicyDefaults(PolicyDefaults value) : IPolicyDefaults
{
    public StubPolicyDefaults()
        : this(PolicyDefaults.BuiltIn)
    {
    }

    public Task<PolicyDefaults> GetAsync(CancellationToken cancellationToken) => Task.FromResult(value);

    public void Invalidate()
    {
    }
}
