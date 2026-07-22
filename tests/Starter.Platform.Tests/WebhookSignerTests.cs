using System.Security.Cryptography;
using System.Text;
using Shouldly;
using Starter.Platform.Webhooks;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The delivery signature (webhooks.md section 5): HMAC-SHA256 over
/// <c>"{timestamp}.{body}"</c>, lowercase hex, in the Stripe-style
/// <c>t=&lt;unix&gt;,v1=&lt;hex&gt;</c> header. The timestamp is part of the signed input,
/// so it cannot be altered without breaking the signature.
/// </summary>
public class WebhookSignerTests
{
    private const string Secret = "whsec_test_secret_value";
    private const long Timestamp = 1_700_000_000;
    private const string Body = """{"id":"d","type":"sample.note.created","occurredAt":"2026-01-01T00:00:00Z","data":{}}""";

    [Fact]
    public void ComputeSignature_MatchesAnIndependentHmac()
    {
        var expected = Convert.ToHexStringLower(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(Secret),
                Encoding.UTF8.GetBytes($"{Timestamp}.{Body}")));

        WebhookSigner.ComputeSignature(Secret, Timestamp, Body).ShouldBe(expected);
    }

    [Fact]
    public void BuildHeader_HasTheStripeShape_WithTheComputedSignature()
    {
        var signature = WebhookSigner.ComputeSignature(Secret, Timestamp, Body);

        WebhookSigner.BuildHeader(Secret, Timestamp, Body).ShouldBe($"t={Timestamp},v1={signature}");
    }

    [Fact]
    public void Signature_IsSensitive_ToTimestampBodyAndSecret()
    {
        var baseline = WebhookSigner.ComputeSignature(Secret, Timestamp, Body);

        // A different timestamp, body, or secret each yields a different signature - the
        // timestamp is signed, not merely transported.
        WebhookSigner.ComputeSignature(Secret, Timestamp + 1, Body).ShouldNotBe(baseline);
        WebhookSigner.ComputeSignature(Secret, Timestamp, Body + " ").ShouldNotBe(baseline);
        WebhookSigner.ComputeSignature(Secret + "x", Timestamp, Body).ShouldNotBe(baseline);
    }

    [Fact]
    public void ComputeSignature_IsDeterministic()
    {
        WebhookSigner.ComputeSignature(Secret, Timestamp, Body)
            .ShouldBe(WebhookSigner.ComputeSignature(Secret, Timestamp, Body));
    }
}
