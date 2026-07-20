using ArchUnitNET.Fluent;
using ArchUnitNET.xUnitV3;
using Shouldly;
using Xunit;
using static ArchUnitNET.Fluent.ArchRuleDefinition;

namespace Starter.Architecture.Tests;

/// <summary>
/// HLD 3.2 rule 1 at the IL level (doc 12 section 5), per ADR-0011's
/// composition-mediated call convention: a module depends on NO type of
/// another module - not even its Api interface. Cross-module calls are
/// resolved and invoked by the composition layer (Starter.Api/Starter.App),
/// which passes results down as parameters; modules never reference one
/// another. The reflection-based <see cref="DependencyShapeTests"/> prove
/// the same at assembly granularity; this rule fails with the offending
/// TYPE named when a dependency sneaks in below assembly level.
/// </summary>
public class ModuleBoundaryTests
{
    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void OtherModules_DependOnNothingInThisModule(Type apiType)
    {
        var targetAssembly = apiType.Assembly;
        var otherModuleAssemblies = StarterModules.ApiTypes
            .Select(other => other.Assembly)
            .Where(assembly => assembly != targetAssembly)
            .Distinct()
            .ToArray();

        // Guards the [0] / [1..] split below: with a single module in
        // StarterModules there would be no "other modules" and the rule
        // would be vacuous, which should read as a broken test setup, not
        // a pass (review round 1, both bots).
        otherModuleAssemblies.ShouldNotBeEmpty();

        IArchRule rule = Types()
            .That().ResideInAssembly(otherModuleAssemblies[0], otherModuleAssemblies[1..])
            .Should().NotDependOnAny(
                Types().That().ResideInAssembly(targetAssembly))
            .Because($"modules never depend on {targetAssembly.GetName().Name}: cross-module calls "
                + "are composition-mediated (ADR-0011; HLD 3.2 rule 1; doc 12 section 5)");

        rule.Check(StarterArchitecture.Instance);
    }
}
