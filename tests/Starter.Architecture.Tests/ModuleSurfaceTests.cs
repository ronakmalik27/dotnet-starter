using Shouldly;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// LLD section 1 / ADR-0011: each module exposes exactly its
/// I&lt;Module&gt;Api interface plus its &lt;Module&gt;Module bootstrap
/// class; everything else is internal. Enforced by enumerating exported
/// types, so a public type added anywhere in a module fails the build
/// until it is either made internal or is part of the sanctioned surface.
/// </summary>
public class ModuleSurfaceTests
{
    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void Module_ExportedTypes_AreExactlyItsApiAndBootstrapClass(Type apiInterface)
    {
        var assembly = apiInterface.Assembly;

        apiInterface.IsInterface.ShouldBeTrue();
        var moduleClass = ModuleClassOf(apiInterface);
        assembly.GetExportedTypes().ShouldBe([apiInterface, moduleClass], ignoreOrder: true);
    }

    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void ModuleApi_Name_FollowsTheIModuleApiConvention(Type apiInterface)
    {
        // Starter.<Module> assembly exposes I<Module>Api (doc 13 section 5:
        // grep-ability across docs, schema, code, and events).
        var moduleName = ModuleNameOf(apiInterface);

        apiInterface.Name.ShouldBe($"I{moduleName}Api");
    }

    [Theory]
    [MemberData(nameof(StarterModules.ApiTypeData), MemberType = typeof(StarterModules))]
    public void ModuleBootstrapClass_IsStatic_AndFollowsTheModuleConvention(Type apiInterface)
    {
        // ADR-0011: the bootstrap class is Starter.<Module>.<Module>Module,
        // static (an extension holder), the module's one registration entry.
        var moduleClass = ModuleClassOf(apiInterface);

        moduleClass.IsAbstract.ShouldBeTrue();
        moduleClass.IsSealed.ShouldBeTrue();
    }

    private static string ModuleNameOf(Type apiInterface) =>
        apiInterface.Assembly.GetName().Name!["Starter.".Length..];

    private static Type ModuleClassOf(Type apiInterface)
    {
        var moduleName = ModuleNameOf(apiInterface);
        var moduleClass = apiInterface.Assembly.GetType($"Starter.{moduleName}.{moduleName}Module");

        moduleClass.ShouldNotBeNull(
            $"Starter.{moduleName} must export its {moduleName}Module bootstrap class (ADR-0011)");
        return moduleClass;
    }
}
