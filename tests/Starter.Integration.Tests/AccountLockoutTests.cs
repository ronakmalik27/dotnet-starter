using System.Net;
using System.Net.Http.Json;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Login lockout (role-templates-and-policy-defaults.md section 4), driven through
/// the real login endpoint. Proves: N wrong passwords lock the credential and
/// further attempts fail even with the RIGHT password while locked; the locked
/// response is the SAME generic 401 as a wrong password (enumeration-safe); a
/// correct password after locked_until elapses (the lock pinned into the past)
/// succeeds and resets the counter; a successful login resets a sub-threshold
/// counter; and a Google-only credential is never locked (lockout is scoped to the
/// password auth_method).
/// <para>
/// Lockout state lives on the per-user password auth_method row, so these tests are
/// isolated to their own fresh accounts and never touch the shared global policy.
/// The default platform lockout threshold is 10 attempts.
/// </para>
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class AccountLockoutTests(StarterAppFixture fixture)
{
    private const int MaxAttempts = 10;
    private const string WrongPassword = "definitely-not-the-right-password";

    [Fact]
    public async Task NWrongPasswords_Lock_AndACorrectPasswordStillFails_WithTheSameGeneric401()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("lockout");
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        // N wrong attempts lock the credential; capture the last wrong-password 401's
        // problem type to compare against the locked response.
        string? wrongType = null;
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var wrong = await LoginAsync(email, WrongPassword, cancellationToken);
            wrong.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
            wrongType = await ProblemTypeAsync(wrong, cancellationToken);
        }

        (await LockedRowCountAsync(userId, cancellationToken)).ShouldBe(1);

        // The RIGHT password is now refused while locked - and with the SAME generic
        // 401 body a wrong password gives, so the lock is not an enumeration oracle.
        var lockedOut = await LoginAsync(email, TenantWorkflow.Password, cancellationToken);
        lockedOut.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await ProblemTypeAsync(lockedOut, cancellationToken)).ShouldBe(wrongType);
    }

    [Fact]
    public async Task CorrectPasswordAfterLockElapses_Succeeds_AndResetsTheCounter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("lockout-elapse");
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            (await LoginAsync(email, WrongPassword, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        (await LockedRowCountAsync(userId, cancellationToken)).ShouldBe(1);

        // Pin the clock: push locked_until into the past so the lock has "elapsed".
        // Auto-unlock is implicit (locked_until <= now), so the next attempt is allowed.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update identity.auth_methods set locked_until = now() - interval '1 hour' "
            + "where user_id = @uid and kind = 'password'",
            cancellationToken,
            ("uid", userId));

        var success = await LoginAsync(email, TenantWorkflow.Password, cancellationToken);
        success.StatusCode.ShouldBe(HttpStatusCode.OK);

        // The successful login reset the counter and cleared the lock.
        (await ResetRowCountAsync(userId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task SuccessfulLogin_ResetsASubThresholdCounter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("lockout-reset");
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        // Three failures - below the threshold, so NOT locked.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            (await LoginAsync(email, WrongPassword, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        (await CountAsync(
            "failed_attempts = 3 and locked_until is null", userId, "password", cancellationToken)).ShouldBe(1);

        // A correct login clears the accrued count.
        (await LoginAsync(email, TenantWorkflow.Password, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ResetRowCountAsync(userId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task GoogleCredential_IsUnaffectedByPasswordLockout()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("lockout-google");
        var token = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        // Give the account a second, Google credential alongside the password one.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "insert into identity.auth_methods (id, user_id, kind, provider_subject, created_at) "
            + "values (@id, @uid, 'google', @sub, now())",
            cancellationToken,
            ("id", Guid.CreateVersion7()),
            ("uid", userId),
            ("sub", $"google-{Guid.NewGuid():N}"));

        // Lock the PASSWORD credential.
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            (await LoginAsync(email, WrongPassword, cancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        (await LockedRowCountAsync(userId, cancellationToken)).ShouldBe(1);

        // The Google credential is untouched: lockout is scoped to the password row.
        (await ResetRowCountAsync(userId, cancellationToken, kind: "google")).ShouldBe(1);
    }

    private Task<HttpResponseMessage> LoginAsync(string email, string password, CancellationToken cancellationToken) =>
        fixture.Client.PostAsJsonAsync("/api/v1/auth/login", new { email, password }, cancellationToken);

    private static async Task<string?> ProblemTypeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.TryGetProperty("type", out var type) ? type.GetString() : null;
    }

    private Task<long> LockedRowCountAsync(Guid userId, CancellationToken cancellationToken) =>
        CountAsync($"failed_attempts >= {MaxAttempts} and locked_until is not null", userId, "password", cancellationToken);

    private Task<long> ResetRowCountAsync(Guid userId, CancellationToken cancellationToken, string kind = "password") =>
        CountAsync("failed_attempts = 0 and locked_until is null", userId, kind, cancellationToken);

    private Task<long> CountAsync(
        string predicate, Guid userId, string kind, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            $"select count(*) from identity.auth_methods where user_id = @uid and kind = @kind and {predicate}",
            cancellationToken,
            ("uid", userId),
            ("kind", kind));
}
