using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Starter.Identity.Tokens;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// Claim construction: ES256, 15-minute expiry, exactly
/// sub / sid / ver, and no role claims.
/// </summary>
public class AccessTokenIssuerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 14, 10, 0, 0, TimeSpan.Zero);

    private static readonly ECDsaSecurityKey Key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    private static readonly Guid UserId = Guid.Parse("019807e0-0000-7000-8000-000000000001");

    private static readonly Guid SessionId = Guid.Parse("019807e0-0000-7000-8000-000000000002");

    private static JsonWebToken Issue() =>
        new(new AccessTokenIssuer(Key).Issue(UserId, SessionId, tokenVersion: 3, Now));

    [Fact]
    public void Issue_CarriesSubSidVer()
    {
        var token = Issue();

        token.Subject.ShouldBe(UserId.ToString());
        token.GetClaim(StarterClaims.Sid).Value.ShouldBe(SessionId.ToString());
        token.GetClaim(StarterClaims.Ver).Value.ShouldBe("3");
    }

    [Fact]
    public void Issue_ExpiresInFifteenMinutes()
    {
        var token = Issue();

        token.ValidTo.ShouldBe(Now.UtcDateTime.AddMinutes(15));
        token.IssuedAt.ShouldBe(Now.UtcDateTime);
    }

    [Fact]
    public void Issue_UsesEs256_AndTheStarterIssuerAudience()
    {
        var token = Issue();

        token.Alg.ShouldBe(SecurityAlgorithms.EcdsaSha256);
        token.Issuer.ShouldBe(StarterAuth.Issuer);
        token.Audiences.ShouldBe([StarterAuth.Audience]);
    }

    [Fact]
    public void Issue_WithoutTenant_OmitsTid()
    {
        // A tenant-less session (login) carries no tid, so tenant resolution
        // falls back to another source.
        var token = Issue();

        token.Claims.ShouldNotContain(claim => claim.Type == StarterClaims.Tid);
    }

    [Fact]
    public void Issue_WithTenant_CarriesTid()
    {
        var tenantId = Guid.Parse("019807e0-0000-7000-8000-0000000000aa");

        var token = new JsonWebToken(
            new AccessTokenIssuer(Key).Issue(UserId, SessionId, tokenVersion: 3, Now, tenantId));

        token.GetClaim(StarterClaims.Tid).Value.ShouldBe(tenantId.ToString());
        // The other claims are unchanged: tid is additive.
        token.Subject.ShouldBe(UserId.ToString());
        token.GetClaim(StarterClaims.Sid).Value.ShouldBe(SessionId.ToString());
        token.GetClaim(StarterClaims.Ver).Value.ShouldBe("3");
    }

    [Fact]
    public void Issue_CarriesNoRoleClaims()
    {
        // Roles are scoped per-entity, resolved per-request - never baked
        // into the token.
        var token = Issue();

        token.Claims.ShouldNotContain(claim =>
            claim.Type.Contains("role", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Issue_ValidatesAgainstThePublicKey_WithTheVerifierRules()
    {
        // Round-trip through the exact validation parameters the platform
        // verifier uses, minus lifetime (this test pins claims, not time).
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(
            new AccessTokenIssuer(Key).Issue(UserId, SessionId, 1, DateTimeOffset.UtcNow),
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
