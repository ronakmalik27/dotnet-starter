using System.Reflection;
using ArchUnitNET.Loader;

namespace Starter.Architecture.Tests;

/// <summary>
/// The ArchUnitNET architecture under test, loaded once (ArchLoader parses
/// IL with Mono.Cecil, so the load is the expensive step; xunit runs test
/// classes in parallel against this shared immutable snapshot). Covers every
/// production assembly: kernel, platform, endpoint layer, host, and the
/// modules from <see cref="StarterModules"/>.
/// </summary>
public static class StarterArchitecture
{
    // Fully qualified: inside the Starter.Architecture.Tests namespace the
    // bare name Architecture binds to the Starter.Architecture namespace.
    public static ArchUnitNET.Domain.Architecture Instance { get; } = new ArchLoader()
        .LoadAssemblies([
            typeof(Starter.SharedKernel.Ids).Assembly,
            typeof(Starter.Platform.Data.ModuleDbContext).Assembly,
            Assembly.Load(new AssemblyName("Starter.Api")),
            Assembly.Load(new AssemblyName("Starter.App")),
            .. StarterModules.ApiTypes.Select(apiType => apiType.Assembly),
        ])
        .Build();
}
