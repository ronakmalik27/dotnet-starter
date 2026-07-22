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
/// bypassing the tenant boundary. This fails the build if any type in the fully-
/// banned module assemblies (Starter.Identity, Starter.Sample) or the endpoint
/// layer (Starter.Api) references it.
/// <para>
/// Starter.Tenancy is the exception, and a narrow one: crossing tenants IS its
/// job for the control plane (multi-tenancy.md section 10), but only for a named
/// allowlist of control-plane types - the self-serve <c>TenantProvisioner</c>, the
/// <c>MembershipDirectory</c>, the <c>InvitationAcceptor</c>, and the platform
/// super-admin plane (<c>PlatformAdminDirectory</c>, <c>PlatformAdminService</c>,
/// and the <c>ImpersonationGrantReader</c>). Every OTHER Tenancy type stays
/// banned, so the allowlist is the literal, enforced definition of "explicitly
/// cross-tenant platform code". Only the composition root (Starter.App) is
/// otherwise allowed.
/// </para>
/// <para>
/// This walks IL with Mono.Cecil directly rather than the ArchUnitNET fluent
/// model, for the same reason <see cref="BannedApiTests"/> walks dependencies
/// directly: the fluent NotDependOnAny does not see a type used only as a
/// generic argument at a call site (the idiomatic
/// <c>GetRequiredService&lt;BypassDataSource&gt;()</c> vector), so a fluent rule
/// would pass vacuously and give false confidence. Cecil surfaces the generic
/// argument in the instruction operand, so this catches it - including the
/// compiler-generated async state machines nested under the allowlisted types.
/// </para>
/// </summary>
public class BypassDataSourceContainmentTests
{
    private const string BypassTypeFullName = "Starter.Platform.Tenancy.BypassDataSource";

    // The only types permitted to touch the bypass data source, all in
    // Starter.Tenancy and all genuinely cross-tenant control-plane work:
    // - the self-serve provisioner (a boundary must exist before any tenant context);
    // - the membership directory (the mint check keys on a tenant the caller holds
    //   no tid for yet, and the tenant-status check the same);
    // - the invitation acceptor (the invitee is not yet a member, so the token
    //   lookup and seat check cross the boundary);
    // - the platform-admin directory (the RequirePlatformAdmin gate reads
    //   platform.platform_admins, a no-RLS platform table);
    // - the platform-admin service (cross-tenant tenant lifecycle, the platform-
    //   admin roster, and the impersonation audit spine);
    // - the impersonation grant reader (the per-request guard re-checks a grant
    //   on the no-RLS platform table).
    private static readonly string[] TenancyAllowlist =
    [
        "Starter.Tenancy.ControlPlane.TenantProvisioner",
        "Starter.Tenancy.ControlPlane.MembershipDirectory",
        "Starter.Tenancy.ControlPlane.InvitationAcceptor",
        "Starter.Tenancy.ControlPlane.PlatformAdminDirectory",
        "Starter.Tenancy.ControlPlane.PlatformAdminService",
        "Starter.Tenancy.ControlPlane.ImpersonationGrantReader",
    ];

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

    [Fact]
    public void Tenancy_ReferencesBypass_OnlyFromTheControlPlaneAllowlist()
    {
        var tenancy = typeof(Starter.Tenancy.ITenancyApi).Assembly.Location;

        var hits = ReferencesToBypass(tenancy);
        var violations = hits.Where(hit => !IsAllowlisted(hit)).Distinct().ToList();

        violations.ShouldBeEmpty(
            "only the allowlisted control-plane types (the provisioner, membership directory, invitation "
            + "acceptor, and the platform super-admin plane) may reach the bypass data source; every other "
            + "Tenancy type is request/consumer code and stays bound by the tenant boundary "
            + "(multi-tenancy.md sections 2 and 10)");

        // Guards against a vacuous allowlist: if the allowlisted types no longer
        // use the bypass source (a refactor that moved the cross-tenant work),
        // the allowlist is dead and this rule would silently protect nothing.
        var allowlistedHits = hits.Where(IsAllowlisted).ToList();
        allowlistedHits.ShouldNotBeEmpty(
            "the allowlisted control-plane types must actually use the bypass data source, "
            + "or the allowlist is stale");
    }

    private static bool IsAllowlisted(string hit) =>
        TenancyAllowlist.Any(allowed =>
            hit.StartsWith(allowed, StringComparison.Ordinal)
            && hit.Length > allowed.Length
            // The hit is "<type>.<member> (...)"; the char after the type name
            // is '.' for the type's own members, or '/' '+' for a nested
            // compiler-generated type (the async state machine). This avoids a
            // prefix collision with a hypothetical "TenantProvisionerOther".
            && hit[allowed.Length] is '.' or '/' or '+');

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
