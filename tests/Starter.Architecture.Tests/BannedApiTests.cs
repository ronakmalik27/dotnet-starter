using ArchUnitNET.Domain.Dependencies;
using Shouldly;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// Banned-API rules, IL-level via the ArchUnitNET domain model: reflection
/// sees signatures, these rules see method bodies. Time flows only through
/// the SharedKernel Clock (determinism) and ids only through the
/// SharedKernel Ids UUIDv7 helper (B-tree locality), so the raw BCL calls
/// are banned everywhere else - including compiler-generated closure and
/// state-machine types, which live in the calling assembly and are scanned
/// like any other type. Walks MethodCallDependency directly instead of the
/// fluent Should().NotCallAny(MethodMembers()...) form because the fluent
/// member provider only enumerates members of LOADED assemblies: BCL
/// targets like DateTime.get_Now are not in it, so that rule form passes
/// vacuously (verified red/green during initial development).
/// </summary>
public class BannedApiTests
{
    private const string SharedKernelAssembly = "Starter.SharedKernel";

    public static TheoryData<string, string> BannedCalls => new()
    {
        // The banned-call list, plus the equivalent reads a review round
        // flagged: DateTimeOffset.Now/UtcNow and DateTime.Today are
        // the same wall-clock read (all current time routes through
        // Clock), and Guid.CreateVersion7 outside the kernel
        // would bypass Ids, the single place id versioning lives. The
        // CreateVersion7 fragment has no closing paren so both overloads
        // (parameterless and DateTimeOffset) match.
        { "DateTime.Now", "System.DateTime::get_Now()" },
        { "DateTime.UtcNow", "System.DateTime::get_UtcNow()" },
        { "DateTime.Today", "System.DateTime::get_Today()" },
        { "DateTimeOffset.Now", "System.DateTimeOffset::get_Now()" },
        { "DateTimeOffset.UtcNow", "System.DateTimeOffset::get_UtcNow()" },
        { "Stopwatch.StartNew", "System.Diagnostics.Stopwatch::StartNew()" },
        // The constructor closes the new Stopwatch() + Start() bypass of
        // the StartNew ban; newobj is a MethodCallDependency to .ctor in
        // the ArchUnitNET model.
        { "new Stopwatch", "System.Diagnostics.Stopwatch::.ctor()" },
        { "Guid.NewGuid", "System.Guid::NewGuid()" },
        { "Guid.CreateVersion7", "System.Guid::CreateVersion7(" },
    };

    [Theory]
    [MemberData(nameof(BannedCalls))]
    public void OutsideSharedKernel_BannedBclCall_IsNeverInvoked(string bannedCall, string ilFullNameFragment)
    {
        var violations = CallsMatching(ilFullNameFragment, bannedCall, SharedKernelAssembly);

        violations.ShouldBeEmpty(
            $"{bannedCall} is banned outside Starter.SharedKernel "
            + "(Clock owns time, Ids owns id minting)");
    }

    [Fact]
    public void OutsideKernelAndCompositionRoot_TimeProviderSystem_IsNeverRead()
    {
        // TimeProvider.System is the wall clock BEHIND the Clock
        // abstraction, so reading it is the same bypass as
        // DateTime.UtcNow. Two sanctioned readers exist by design: the
        // kernel (Clock.System wraps it) and the Starter.App composition
        // root, which wires the singleton into DI exactly once;
        // everything downstream injects Clock or TimeProvider.
        var violations = CallsMatching(
            "System.TimeProvider::get_System()",
            "TimeProvider.System",
            SharedKernelAssembly,
            "Starter.App");

        violations.ShouldBeEmpty(
            "TimeProvider.System is banned outside Starter.SharedKernel and "
            + "the Starter.App composition root (inject Clock or TimeProvider)");
    }

    private static List<string> CallsMatching(
        string ilFullNameFragment,
        string bannedCall,
        params string[] allowedAssemblies)
    {
        // TargetMember.FullName is Cecil-shaped:
        // "System.DateTime System.DateTime::get_Now()".
        return StarterArchitecture.Instance.Types
            .Where(type => !allowedAssemblies.Contains(type.Assembly.Name))
            .SelectMany(type => type.Dependencies
                .OfType<MethodCallDependency>()
                .Where(call => call.TargetMember.FullName.Contains(ilFullNameFragment, StringComparison.Ordinal))
                .Select(call => $"{type.FullName} calls {bannedCall}"))
            .Distinct()
            .ToList();
    }

    [Fact]
    public void BannedCallScan_SeesSharedKernelsOwnUses_SoTheScanIsNotVacuous()
    {
        // Self-test of the scan mechanics: Ids.NewId() calls
        // Guid.CreateVersion7 and Clock reads TimeProvider, so the kernel
        // assembly MUST show method-call dependencies. If ArchUnitNET ever
        // stops surfacing MethodCallDependency (a loader regression or a
        // packaging change), this canary fails instead of every rule above
        // passing vacuously.
        var kernelCalls = StarterArchitecture.Instance.Types
            .Where(type => type.Assembly.Name == SharedKernelAssembly)
            .SelectMany(type => type.Dependencies.OfType<MethodCallDependency>())
            .ToList();

        kernelCalls.ShouldNotBeEmpty();
    }
}
