using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// Claim construction: ES256, exactly sub / sid / ver, no role claims, and the
/// access-token lifetime resolved from the platform policy defaults (15 minutes by
/// default) with a tenant override tightening it (role-templates-and-policy-defaults.md
/// sections 3, 5).
/// </summary>
public class AccessTokenIssuerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 14, 10, 0, 0, TimeSpan.Zero);

    private static readonly ECDsaSecurityKey Key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    private static readonly Guid UserId = Guid.Parse("019807e0-0000-7000-8000-000000000001");

    private static readonly Guid SessionId = Guid.Parse("019807e0-0000-7000-8000-000000000002");

    private static AccessTokenIssuer NewIssuer(PolicyDefaults? policy = null) =>
        new(Key, new StubPolicyDefaults(policy ?? PolicyDefaults.BuiltIn));

    private static async Task<JsonWebToken> IssueAsync(Guid? tenantId = null, int? sessionMaxSeconds = null)
    {
        var minted = await NewIssuer().IssueAsync(
            UserId, SessionId, tokenVersion: 3, Now, tenantId, sessionMaxSeconds, CancellationToken.None);
        return new JsonWebToken(minted.Token);
    }

    [Fact]
    public async Task Issue_CarriesSubSidVer()
    {
        var token = await IssueAsync();

        token.Subject.ShouldBe(UserId.ToString());
        token.GetClaim(StarterClaims.Sid).Value.ShouldBe(SessionId.ToString());
        token.GetClaim(StarterClaims.Ver).Value.ShouldBe("3");
    }

    [Fact]
    public async Task Issue_ExpiresInFifteenMinutes()
    {
        var token = await IssueAsync();

        token.ValidTo.ShouldBe(Now.UtcDateTime.AddMinutes(15));
        token.IssuedAt.ShouldBe(Now.UtcDateTime);
    }

    [Fact]
    public async Task Issue_UsesEs256_AndTheStarterIssuerAudience()
    {
        var token = await IssueAsync();

        token.Alg.ShouldBe(SecurityAlgorithms.EcdsaSha256);
        token.Issuer.ShouldBe(StarterAuth.Issuer);
        token.Audiences.ShouldBe([StarterAuth.Audience]);
    }

    [Fact]
    public async Task Issue_WithoutTenant_OmitsTid()
    {
        // A tenant-less session (login) carries no tid, so tenant resolution
        // falls back to another source.
        var token = await IssueAsync();

        token.Claims.ShouldNotContain(claim => claim.Type == StarterClaims.Tid);
    }

    [Fact]
    public async Task Issue_WithTenant_CarriesTid()
    {
        var tenantId = Guid.Parse("019807e0-0000-7000-8000-0000000000aa");

        var token = await IssueAsync(tenantId);

        token.GetClaim(StarterClaims.Tid).Value.ShouldBe(tenantId.ToString());
        // The other claims are unchanged: tid is additive.
        token.Subject.ShouldBe(UserId.ToString());
        token.GetClaim(StarterClaims.Sid).Value.ShouldBe(SessionId.ToString());
        token.GetClaim(StarterClaims.Ver).Value.ShouldBe("3");
    }

    [Fact]
    public async Task Issue_TenantOverride_ShortensLifetime_ToTheMinimum()
    {
        var tenantId = Guid.Parse("019807e0-0000-7000-8000-0000000000bb");

        // The platform default is 900s; a 300s tenant override tightens it.
        var minted = await NewIssuer().IssueAsync(
            UserId, SessionId, tokenVersion: 3, Now, tenantId, tenantSessionMaxSeconds: 300, CancellationToken.None);

        minted.ExpiresInSeconds.ShouldBe(300);
        new JsonWebToken(minted.Token).ValidTo.ShouldBe(Now.UtcDateTime.AddSeconds(300));
    }

    [Fact]
    public async Task Issue_TenantOverrideAbovePlatform_KeepsThePlatformDefault()
    {
        var tenantId = Guid.Parse("019807e0-0000-7000-8000-0000000000cc");

        // min(platform, override): an override longer than the platform default never
        // widens the lifetime (the write path also rejects it; the mint is defensive).
        var minted = await NewIssuer().IssueAsync(
            UserId, SessionId, tokenVersion: 3, Now, tenantId, tenantSessionMaxSeconds: 100000, CancellationToken.None);

        minted.ExpiresInSeconds.ShouldBe(900);
    }

    [Fact]
    public async Task Issue_PlatformLifetimeChange_ChangesTheExpiry()
    {
        // The lifetime comes from IPolicyDefaults, so a raised platform access-token
        // lifetime is reflected in the token the mint returns.
        var issuer = NewIssuer(PolicyDefaults.BuiltIn with { AccessTokenLifetimeSeconds = 60 });

        var minted = await issuer.IssueAsync(
            UserId, SessionId, tokenVersion: 3, Now, tenantId: null, tenantSessionMaxSeconds: null, CancellationToken.None);

        minted.ExpiresInSeconds.ShouldBe(60);
        new JsonWebToken(minted.Token).ValidTo.ShouldBe(Now.UtcDateTime.AddSeconds(60));
    }

    [Fact]
    public async Task Issue_CarriesNoRoleClaims()
    {
        // Roles are scoped per-entity, resolved per-request - never baked
        // into the token.
        var token = await IssueAsync();

        token.Claims.ShouldNotContain(claim =>
            claim.Type.Contains("role", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Issue_ValidatesAgainstThePublicKey_WithTheVerifierRules()
    {
        // Round-trip through the exact validation parameters the platform
        // verifier uses, minus lifetime (this test pins claims, not time).
        var minted = await NewIssuer().IssueAsync(
            UserId, SessionId, tokenVersion: 1, DateTimeOffset.UtcNow, tenantId: null, tenantSessionMaxSeconds: null, CancellationToken.None);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(
            minted.Token,
            new TokenValidationParameters
            {
                ValidIssuer = StarterAuth.Issuer,
                ValidAudience = StarterAuth.Audience,
                IssuerSigningKey = Key,
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            });

        result.IsValid.ShouldBeTrue();
    }
}
