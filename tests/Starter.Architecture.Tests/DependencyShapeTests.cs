using System.Reflection;
using Shouldly;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// Project-reference shape rules. These read
/// compiled assembly metadata, so they hold whatever the source looks like.
/// The compiler prunes unused references from metadata, which only makes
/// these subset assertions stricter.
/// </summary>
public class DependencyShapeTests
{
    [Fact]
    public void SharedKernel_ReferencedAssemblies_ContainNothingFromTheSolution()
    {
        // The kernel is the bottom of the dependency graph: it references
        // nothing else in the solution.
        var references = typeof(Starter.SharedKernel.Ids).Assembly.GetReferencedAssemblies();

        references.ShouldAllBe(
            reference => !reference.Name!.StartsWith("Starter", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void Module_SolutionReferences_AreOnlySharedKernelAndPlatform(Type moduleApiType)
    {
        // Modules never reference another module. Cross-module calls are
        // composition-mediated: the
        // Api/App layer resolves I<Module>Api instances and passes
        // results down as parameters.
        var solutionReferences = moduleApiType.Assembly.GetReferencedAssemblies()
            .Where(reference => reference.Name!.StartsWith("Starter", StringComparison.Ordinal));

        solutionReferences.ShouldAllBe(
            reference => reference.Name == "Starter.SharedKernel" || reference.Name == "Starter.Platform");
    }

    [Fact]
    public void Platform_SolutionReferences_AreOnlySharedKernel()
    {
        var assembly = Assembly.Load(new AssemblyName("Starter.Platform"));

        var solutionReferences = assembly.GetReferencedAssemblies()
            .Where(reference => reference.Name!.StartsWith("Starter", StringComparison.Ordinal));

        solutionReferences.ShouldAllBe(reference => reference.Name == "Starter.SharedKernel");
    }
}
