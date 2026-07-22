using System.Reflection;
using Mono.Cecil;
using Shouldly;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// The RLS-exempt bypass data source must be unreachable from request- and
/// consumer-scoped code (multi-tenancy.md section 2: crossing tenants is a role
/// reached through a separate connection source, never an in-band switch). It
/// is a public root singleton, so nothing but this rule stops a module handler
/// - or a consumer, which is handed an IServiceProvider - from resolving it and
/// bypassing the tenant boundary. This fails the build if any type in a module
/// assembly (Starter.Identity, Starter.Sample) or the endpoint layer
/// (Starter.Api) references it. Only the composition root (Starter.App) and
/// explicitly cross-tenant platform code may. It matters more once the control
/// plane (increments 3-4) runs on the bypass path.
/// <para>
/// This walks IL with Mono.Cecil directly rather than the ArchUnitNET fluent
/// model, for the same reason <see cref="BannedApiTests"/> walks dependencies
/// directly: the fluent NotDependOnAny does not see a type used only as a
/// generic argument at a call site (the idiomatic
/// <c>GetRequiredService&lt;BypassDataSource&gt;()</c> vector), so a fluent rule
/// would pass vacuously and give false confidence. Cecil surfaces the generic
/// argument in the instruction operand, so this catches it.
/// </para>
/// </summary>
public class BypassDataSourceContainmentTests
{
    private const string BypassTypeFullName = "Starter.Platform.Tenancy.BypassDataSource";

    [Fact]
    public void ModulesAndApi_DoNotReference_TheBypassDataSource()
    {
        var restricted = new[]
        {
            typeof(Starter.Identity.IIdentityApi).Assembly.Location,
            typeof(Starter.Sample.ISampleApi).Assembly.Location,
            Assembly.Load(new AssemblyName("Starter.Api")).Location,
        };

        // Guards against a vacuous rule: if a restricted assembly stopped
        // loading, the "no reference" claim would pass trivially.
        restricted.Length.ShouldBe(3);

        var violations = restricted.SelectMany(ReferencesToBypass).Distinct().ToList();

        violations.ShouldBeEmpty(
            "the RLS-exempt bypass data source must be unreachable from request/consumer code "
            + "(multi-tenancy.md section 2); only the composition root and explicitly cross-tenant "
            + "platform code may resolve it");
    }

    private static List<string> ReferencesToBypass(string assemblyPath)
    {
        var hits = new List<string>();
        using var module = ModuleDefinition.ReadModule(assemblyPath);
        foreach (var type in module.GetTypes())
        {
            foreach (var field in type.Fields.Where(field => Mentions(field.FieldType)))
            {
                hits.Add($"{type.FullName}.{field.Name} (field type)");
            }

            foreach (var method in type.Methods)
            {
                if (Mentions(method.ReturnType) || method.Parameters.Any(p => Mentions(p.ParameterType)))
                {
                    hits.Add($"{type.FullName}.{method.Name} (signature)");
                }

                if (!method.HasBody)
                {
                    continue;
                }

                // The load-bearing scan: any operand mentioning the bypass type
                // - a typeof, a cast, a new, a member access, or the generic
                // argument of a GetService<BypassDataSource>() call.
                foreach (var instruction in method.Body.Instructions)
                {
                    if (instruction.Operand?.ToString() is { } operand
                        && operand.Contains(BypassTypeFullName, StringComparison.Ordinal))
                    {
                        hits.Add($"{type.FullName}.{method.Name} (IL {instruction.OpCode})");
                    }
                }
            }
        }

        return hits;
    }

    private static bool Mentions(TypeReference type) =>
        type.FullName.Contains(BypassTypeFullName, StringComparison.Ordinal);
}
