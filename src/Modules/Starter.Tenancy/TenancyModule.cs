using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Starter.Tenancy.Admin;
using Starter.Tenancy.ControlPlane;
using Starter.Tenancy.Invitations;
using Starter.Tenancy.Rbac;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Tenancy;

namespace Starter.Tenancy;

/// <summary>
/// The Tenancy module's bootstrap surface: the single public entry the
/// composition root calls. It contributes the module's DbContext and schema
/// descriptor through the shared module-bootstrap path and registers the
/// control-plane slices behind ITenancyApi.
/// </summary>
public static class TenancyModule
{
    /// <summary>
    /// Registers the module against <paramref name="connectionString"/> (the
    /// request-role connection, for the scoped context). The self-serve
    /// provisioner, the membership directory, and the invitation acceptor
    /// additionally inject the platform <c>BypassDataSource</c> singleton (already
    /// registered by the composition root) for their explicitly cross-tenant
    /// work; the OutboxWriter and the platform Identity ports are resolved from
    /// the same host. <paramref name="configuration"/> carries the
    /// Tenancy:Invitations link template (guarded for null exactly like the
    /// Identity email options: the module still boots with the default).
    /// </summary>
    public static IServiceCollection AddTenancyModule(
        this IServiceCollection services,
        string connectionString,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddModuleDbContext<TenancyDbContext>(TenancyDbContext.SchemaName, connectionString);

        // The invitation link template (Tenancy:Invitations), validated at
        // startup: the [Required] annotation plus the {token}-placeholder rule.
        // The default satisfies both, so a zero-config host still boots.
        var invitations = services.AddOptions<InvitationEmailOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configuration is not null)
        {
            invitations.Bind(configuration.GetSection(InvitationEmailOptions.SectionName));
        }

        services.AddSingleton<IValidateOptions<InvitationEmailOptions>, InvitationEmailOptionsValidator>();
        services.AddScoped<InvitationEmailComposer>();

        // The platform control-plane options (impersonation window), bound from
        // the Platform section and validated at startup. The default satisfies
        // the annotation, so a zero-config host still boots.
        var platformOptions = services.AddOptions<PlatformAdminOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configuration is not null)
        {
            platformOptions.Bind(configuration.GetSection(PlatformAdminOptions.SectionName));
        }

        // Bypass-path (cross-tenant control plane) slices.
        services.AddScoped<TenantProvisioner>();
        services.AddScoped<MembershipDirectory>();
        services.AddScoped<InvitationAcceptor>();
        services.AddScoped<PlatformAdminDirectory>();
        services.AddScoped<PlatformAdminService>();
        services.AddScoped<ImpersonationGrantReader>();

        // Request-path (RLS-bound) slices.
        services.AddScoped<TenantRoleResolver>();
        services.AddScoped<PermissionResolver>();
        services.AddScoped<CustomRoleService>();
        services.AddScoped<WorkspaceService>();
        services.AddScoped<TeamService>();
        services.AddScoped<TenantAdminService>();

        services.AddScoped<ITenancyApi, TenancyApi>();

        // Bridge the platform-declared role-reader port (used by the layer-3
        // resource handler in the platform) to the request-path resolver, so the
        // platform never references this module and there is one lookup.
        services.AddScoped<ITenantRoleReader>(
            provider => provider.GetRequiredService<TenantRoleResolver>());

        // Bridge the platform-declared permission-resolver port to the request-
        // path resolver, mirroring the role-reader bridge: one resolver, no
        // drift, and the platform never references this module.
        services.AddScoped<IPermissionResolver>(
            provider => provider.GetRequiredService<PermissionResolver>());

        // Bridge the platform-declared workspace-reader port (used by the
        // RequireWorkspace gate) to the request-path workspace service, so the
        // gate's existence check is the same RLS-bound read as the CRUD surface.
        services.AddScoped<IWorkspaceReader>(
            provider => provider.GetRequiredService<WorkspaceService>());

        // Bridge the platform-declared impersonation-guard port (used by the
        // per-request guard middleware in the platform) to the bypass-path grant
        // reader, so the platform never references this module.
        services.AddScoped<IImpersonationGrantReader>(
            provider => provider.GetRequiredService<ImpersonationGrantReader>());

        return services;
    }
}
