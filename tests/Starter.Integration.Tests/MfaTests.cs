using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Shouldly;
using Starter.Identity.Mfa;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// MFA / TOTP (mfa-totp.md), driven through the real endpoints. Proves:
/// enroll does not enforce, confirm enables and returns recovery codes, a wrong
/// code does not confirm; enroll and confirm require the current password
/// (step-up); a confirmed user's login returns an MFA challenge (no session),
/// and mfa-verify with a TOTP or a recovery code issues the session; a burned
/// recovery code never works again; the challenge token is rejected by normal
/// access-token auth; a non-MFA user logs in in one step; the verify step is
/// brute-force locked per user; and disable requires a fresh code and reverts
/// to one step.
/// <para>
/// The test computes codes with the same internal Totp/Base32 helpers the
/// server uses. Login codes are minted for <c>currentStep + 1</c>: that step is
/// inside the server's +/-1 skew window AND strictly above the step the
/// confirming code recorded on last_step, so the replay guard never spuriously
/// rejects a freshly-minted login code that happens to fall in the confirm's
/// 30-second window.
/// </para>
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class MfaTests(StarterAppFixture fixture)
{
    private const string Password = TenantWorkflow.Password;
    private const int MaxAttempts = 10;

    [Fact]
    public async Task Enroll_DoesNotEnforce_Confirm_Enables_AndReturnsRecoveryCodes()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-enroll");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        var (secret, otpauthUri) = await EnrollAsync(token, Password, cancellationToken);
        otpauthUri.ShouldStartWith("otpauth://totp/");
        otpauthUri.ShouldContain("secret=" + secret);
        secret.ShouldNotBeNullOrEmpty();

        // Enrollment alone does not enforce MFA: login still issues a session.
        var beforeConfirm = await LoginAsync(email, Password, cancellationToken);
        beforeConfirm.RootElement.TryGetProperty("accessToken", out _).ShouldBeTrue();

        // A wrong code does not confirm: MFA stays off.
        var wrong = await ConfirmRawAsync(token, Password, WrongCode(secret), cancellationToken);
        wrong.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);
        (await LoginAsync(email, Password, cancellationToken))
            .RootElement.TryGetProperty("accessToken", out _).ShouldBeTrue();

        // The correct code confirms and returns 10 recovery codes, shown once.
        var recoveryCodes = await ConfirmAsync(token, Password, secret, cancellationToken);
        recoveryCodes.Count.ShouldBe(10);
        recoveryCodes.ShouldAllBe(code => code.Replace("-", string.Empty).Length >= 16);

        // MFA is now enforced: login returns a challenge, not a session.
        var afterConfirm = await LoginAsync(email, Password, cancellationToken);
        afterConfirm.RootElement.GetProperty("mfaRequired").GetBoolean().ShouldBeTrue();
        afterConfirm.RootElement.TryGetProperty("accessToken", out _).ShouldBeFalse();
    }

    [Fact]
    public async Task EnrollAndConfirm_RequireTheCurrentPassword_StepUp()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-stepup");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        // Enroll with the WRONG current password is refused (a session alone
        // must not let an attacker enroll their own secret).
        var enrollWrong = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/auth/mfa/enroll", token, new { currentPassword = "not-the-password" }, cancellationToken);
        enrollWrong.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // Enroll properly, then confirm with the WRONG current password (but a
        // VALID code) is still refused: confirm is a step-up too.
        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        var confirmWrong = await ConfirmRawWithPasswordAsync(
            token, "not-the-password", CurrentCode(secret), cancellationToken);
        confirmWrong.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // MFA is still not enabled: login issues a session.
        (await LoginAsync(email, Password, cancellationToken))
            .RootElement.TryGetProperty("accessToken", out _).ShouldBeTrue();
    }

    [Fact]
    public async Task Login_ThenVerifyWithTotp_IssuesTheSession()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-totp-login");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        await ConfirmAsync(token, Password, secret, cancellationToken);

        var challenge = await ChallengeAsync(email, Password, cancellationToken);
        var verify = await VerifyRawAsync(challenge, LoginCode(secret), cancellationToken);
        verify.StatusCode.ShouldBe(HttpStatusCode.OK);

        using var doc = await HttpTestHelpers.ReadJsonAsync(verify, cancellationToken);
        var accessToken = doc.RootElement.GetProperty("accessToken").GetString()!;
        HttpTestHelpers.ReadSubject(accessToken).ShouldBe(userId);
    }

    [Fact]
    public async Task Login_ThenVerifyWithRecoveryCode_IssuesSession_AndBurnsTheCode()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-recovery-login");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        var recoveryCodes = await ConfirmAsync(token, Password, secret, cancellationToken);

        // A recovery code stands in for a TOTP code and issues the session.
        var firstChallenge = await ChallengeAsync(email, Password, cancellationToken);
        var burned = recoveryCodes[0];
        var withRecovery = await VerifyRawAsync(firstChallenge, burned, cancellationToken);
        withRecovery.StatusCode.ShouldBe(HttpStatusCode.OK);

        // Reusing the SAME recovery code fails: it is one-time.
        var reuseChallenge = await ChallengeAsync(email, Password, cancellationToken);
        (await VerifyRawAsync(reuseChallenge, burned, cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.Unauthorized);

        // A DIFFERENT, still-live recovery code works.
        var secondChallenge = await ChallengeAsync(email, Password, cancellationToken);
        (await VerifyRawAsync(secondChallenge, recoveryCodes[1], cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ChallengeToken_IsRejectedByNormalAccessTokenAuth()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-challenge-aud");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        await ConfirmAsync(token, Password, secret, cancellationToken);

        var challenge = await ChallengeAsync(email, Password, cancellationToken);

        // The challenge token carries aud=mfa-challenge; presenting it as an
        // access token to a normal authenticated endpoint is a 401 - it can
        // never act as an access token.
        var asAccessToken = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/auth/mfa/enroll", challenge, new { currentPassword = Password }, cancellationToken);
        asAccessToken.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task NonMfaUser_LogsInOneStep()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-none");
        await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        // No enrollment: login issues a session directly, with no mfaRequired.
        var login = await LoginAsync(email, Password, cancellationToken);
        login.RootElement.TryGetProperty("accessToken", out _).ShouldBeTrue();
        login.RootElement.TryGetProperty("mfaRequired", out _).ShouldBeFalse();
    }

    [Fact]
    public async Task Verify_IsBruteForceLocked_PerUser_AndSuccessResets()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-bruteforce");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);
        var userId = HttpTestHelpers.ReadSubject(token);

        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        await ConfirmAsync(token, Password, secret, cancellationToken);

        // N wrong codes against one challenge lock the MFA step.
        var challenge = await ChallengeAsync(email, Password, cancellationToken);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            (await VerifyRawAsync(challenge, WrongCode(secret), cancellationToken)).StatusCode
                .ShouldBe(HttpStatusCode.Unauthorized);
        }

        (await LockedRowCountAsync(userId, cancellationToken)).ShouldBe(1);

        // A fresh challenge does NOT reset the count, and a CORRECT code fails
        // while locked (the lock is per user, not per challenge).
        var freshChallenge = await ChallengeAsync(email, Password, cancellationToken);
        (await VerifyRawAsync(freshChallenge, LoginCode(secret), cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.Unauthorized);
        (await LockedRowCountAsync(userId, cancellationToken)).ShouldBe(1);

        // Pin locked_until into the past (auto-unlock is implicit), then a
        // correct code succeeds and resets the counter and the lock.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update identity.mfa_credentials set locked_until = now() - interval '1 hour' where user_id = @uid",
            cancellationToken,
            ("uid", userId));

        var unlockedChallenge = await ChallengeAsync(email, Password, cancellationToken);
        (await VerifyRawAsync(unlockedChallenge, LoginCode(secret), cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.OK);
        (await ResetRowCountAsync(userId, cancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task Disable_RequiresAFreshCode_AndRevertsToOneStep()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-disable");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        var (secret, _) = await EnrollAsync(token, Password, cancellationToken);
        await ConfirmAsync(token, Password, secret, cancellationToken);

        // A wrong code does not disable.
        var wrong = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/auth/mfa/disable", token, new { code = WrongCode(secret) }, cancellationToken);
        wrong.StatusCode.ShouldBe(HttpStatusCode.UnprocessableEntity);

        // A fresh valid code disables MFA.
        var disable = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/auth/mfa/disable", token, new { code = LoginCode(secret) }, cancellationToken);
        disable.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // Login is one step again.
        (await LoginAsync(email, Password, cancellationToken))
            .RootElement.TryGetProperty("accessToken", out _).ShouldBeTrue();
    }

    [Fact]
    public async Task ReEnroll_DoesNotDisturbAnActiveSecret()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var email = TenantWorkflow.FreshEmail("mfa-reenroll");
        var token = await fixture.RegisterVerifyLoginAsync(email, Password, cancellationToken);

        var (activeSecret, _) = await EnrollAsync(token, Password, cancellationToken);
        await ConfirmAsync(token, Password, activeSecret, cancellationToken);

        // Begin a fresh enrollment (a new pending secret) while confirmed.
        var (pendingSecret, _) = await EnrollAsync(token, Password, cancellationToken);
        pendingSecret.ShouldNotBe(activeSecret);

        // MFA still enforced, and the ACTIVE secret still verifies: the pending
        // re-enroll disturbed neither the active secret nor its confirmed state.
        var challenge = await ChallengeAsync(email, Password, cancellationToken);
        (await VerifyRawAsync(challenge, LoginCode(activeSecret), cancellationToken)).StatusCode
            .ShouldBe(HttpStatusCode.OK);
    }

    // --- code helpers ----------------------------------------------------

    private static string CurrentCode(string secret) =>
        Totp.Generate(Base32.Decode(secret), Totp.CurrentStep(DateTimeOffset.UtcNow));

    // A login code one step ahead of the current step: inside the +/-1 skew
    // window and strictly above the step the confirming code recorded, so the
    // replay guard never rejects it even when confirm and verify land in the
    // same 30-second window.
    private static string LoginCode(string secret) =>
        Totp.Generate(Base32.Decode(secret), Totp.CurrentStep(DateTimeOffset.UtcNow) + 1);

    private static string WrongCode(string secret)
    {
        var bytes = Base32.Decode(secret);
        var step = Totp.CurrentStep(DateTimeOffset.UtcNow);
        var window = new HashSet<string>(StringComparer.Ordinal);
        for (var offset = -2; offset <= 2; offset++)
        {
            window.Add(Totp.Generate(bytes, step + offset));
        }

        for (var candidate = 0; candidate < 1000; candidate++)
        {
            var code = candidate.ToString("D6", CultureInfo.InvariantCulture);
            if (!window.Contains(code))
            {
                return code;
            }
        }

        throw new InvalidOperationException("Could not find a wrong code outside the skew window.");
    }

    // --- HTTP helpers ----------------------------------------------------

    private async Task<(string Secret, string OtpauthUri)> EnrollAsync(
        string bearer, string password, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/auth/mfa/enroll", bearer, new { currentPassword = password }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return (
            doc.RootElement.GetProperty("secret").GetString()!,
            doc.RootElement.GetProperty("otpauthUri").GetString()!);
    }

    private Task<HttpResponseMessage> ConfirmRawAsync(
        string bearer, string password, string code, CancellationToken cancellationToken) =>
        ConfirmRawWithPasswordAsync(bearer, password, code, cancellationToken);

    private Task<HttpResponseMessage> ConfirmRawWithPasswordAsync(
        string bearer, string password, string code, CancellationToken cancellationToken) =>
        TenantWorkflow.PostJsonAsync(
            fixture,
            "/api/v1/auth/mfa/confirm",
            bearer,
            new { currentPassword = password, code },
            cancellationToken);

    private async Task<IReadOnlyList<string>> ConfirmAsync(
        string bearer, string password, string secret, CancellationToken cancellationToken)
    {
        var response = await ConfirmRawAsync(bearer, password, CurrentCode(secret), cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return [.. doc.RootElement.GetProperty("recoveryCodes").EnumerateArray().Select(item => item.GetString()!)];
    }

    private async Task<JsonDocument> LoginAsync(string email, string password, CancellationToken cancellationToken)
    {
        var response = await fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email, password }, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        return await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
    }

    private async Task<string> ChallengeAsync(string email, string password, CancellationToken cancellationToken)
    {
        using var doc = await LoginAsync(email, password, cancellationToken);
        doc.RootElement.GetProperty("mfaRequired").GetBoolean().ShouldBeTrue();
        return doc.RootElement.GetProperty("challenge").GetString()!;
    }

    private Task<HttpResponseMessage> VerifyRawAsync(
        string challenge, string code, CancellationToken cancellationToken) =>
        fixture.Client.PostAsJsonAsync(
            "/api/v1/auth/mfa/verify", new { challenge, code }, cancellationToken);

    private Task<long> LockedRowCountAsync(Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.mfa_credentials "
            + $"where user_id = @uid and failed_attempts >= {MaxAttempts} and locked_until is not null",
            cancellationToken,
            ("uid", userId));

    private Task<long> ResetRowCountAsync(Guid userId, CancellationToken cancellationToken) =>
        PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from identity.mfa_credentials "
            + "where user_id = @uid and failed_attempts = 0 and locked_until is null",
            cancellationToken,
            ("uid", userId));
}
