using Shouldly;
using Starter.Identity.PasswordReset;
using Starter.Identity.Verification;
using Xunit;

namespace Starter.Identity.Tests;

/// <summary>
/// The custom options validator: both email link templates must carry the
/// literal {token} placeholder - a rule richer than a data annotation. A
/// template without it fails validation (fail-fast at startup), so a tokenless
/// broken link can never reach a recipient. The shipped defaults must pass so
/// a zero-config host still boots.
/// </summary>
public class EmailLinkTemplateValidatorTests
{
    private readonly EmailLinkTemplateValidator _validator = new();

    [Fact]
    public void Verification_TemplateWithToken_Succeeds()
    {
        var options = new VerificationEmailOptions { UrlTemplate = "https://app.example/verify?token={token}" };

        _validator.Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void PasswordReset_TemplateWithToken_Succeeds()
    {
        var options = new PasswordResetEmailOptions { UrlTemplate = "https://app.example/reset?token={token}" };

        _validator.Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Verification_TemplateWithoutToken_Fails()
    {
        var options = new VerificationEmailOptions { UrlTemplate = "https://app.example/verify" };

        var result = _validator.Validate(null, options);

        result.Failed.ShouldBeTrue();
        result.FailureMessage.ShouldContain("{token}");
    }

    [Fact]
    public void PasswordReset_EmptyTemplate_Fails() =>
        _validator.Validate(null, new PasswordResetEmailOptions { UrlTemplate = "" })
            .Failed.ShouldBeTrue();

    [Fact]
    public void ShippedDefaults_Succeed()
    {
        _validator.Validate(null, new VerificationEmailOptions()).Succeeded.ShouldBeTrue();
        _validator.Validate(null, new PasswordResetEmailOptions()).Succeeded.ShouldBeTrue();
    }
}
