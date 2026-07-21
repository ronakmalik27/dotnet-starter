using Microsoft.Extensions.Options;
using Shouldly;
using Starter.Platform.Events;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The duration validation the [Range] annotations cannot cover: every lease,
/// poll, timeout, backoff, and retention span must be strictly positive, and
/// the jitter bound non-negative. The shipped defaults must pass (a zero-config
/// host still boots); a zero or negative duration must fail with the offending
/// field named.
/// </summary>
public class OutboxOptionsValidatorTests
{
    private static readonly OutboxOptionsValidator Validator = new();

    [Fact]
    public void Validate_ShippedDefaults_Succeed()
    {
        var result = Validator.Validate(name: null, new OutboxOptions());

        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Validate_ZeroPollInterval_Fails()
    {
        var options = new OutboxOptions { FastPollInterval = TimeSpan.Zero };

        var result = Validator.Validate(name: null, options);

        result.Failed.ShouldBeTrue();
        result.FailureMessage.ShouldContain(nameof(OutboxOptions.FastPollInterval));
    }

    [Fact]
    public void Validate_NegativeSendTimeout_Fails()
    {
        var options = new OutboxOptions { SlowSendTimeout = TimeSpan.FromSeconds(-1) };

        var result = Validator.Validate(name: null, options);

        result.Failed.ShouldBeTrue();
        result.FailureMessage.ShouldContain(nameof(OutboxOptions.SlowSendTimeout));
    }

    [Fact]
    public void Validate_NegativeMaxJitter_Fails()
    {
        var options = new OutboxOptions { MaxJitter = TimeSpan.FromSeconds(-1) };

        var result = Validator.Validate(name: null, options);

        result.Failed.ShouldBeTrue();
        result.FailureMessage.ShouldContain(nameof(OutboxOptions.MaxJitter));
    }

    [Fact]
    public void Validate_ZeroMaxJitter_Succeeds()
    {
        // Zero jitter is a legitimate "disable jitter" setting, unlike the
        // other durations which must be strictly positive.
        var options = new OutboxOptions { MaxJitter = TimeSpan.Zero };

        var result = Validator.Validate(name: null, options);

        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void Validate_MultipleBadDurations_ReportsEachField()
    {
        var options = new OutboxOptions
        {
            FastPollInterval = TimeSpan.Zero,
            MaxBackoff = TimeSpan.FromSeconds(-5),
            DeliveredRetention = TimeSpan.Zero,
        };

        var result = Validator.Validate(name: null, options);

        result.Failed.ShouldBeTrue();
        result.Failures.ShouldNotBeNull();
        result.Failures.Count().ShouldBe(3);
    }
}
