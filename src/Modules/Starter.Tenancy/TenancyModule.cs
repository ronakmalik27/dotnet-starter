using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Starter.Tenancy.Admin;
using Starter.Tenancy.ControlPlane;
using Starter.Tenancy.Dsar;
using Starter.Tenancy.Invitations;
using Starter.Tenancy.Rbac;
using Starter.Tenancy.ServiceAccounts;
using Starter.Tenancy.Sso;
using Starter.Platform.Auth;
using Starter.Platform.Data;
using Starter.Platform.Dsar;
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

        // The API-key options (Tenancy:ApiKeys), bound when configuration is
        // present; the default (a 5-minute last_used_at throttle) satisfies a
        // zero-config host (service-accounts.md section 6).
        var apiKeys = services.AddOptions<ApiKeyOptions>();
        if (configuration is not null)
        {
            apiKeys.Bind(configuration.GetSection(ApiKeyOptions.SectionName));
        }

        // The DSAR options (Dsar:RetentionDays), validated at startup like the
        // platform options above (data-export-and-erasure.md section 2). The default
        // (30) satisfies the [Range], so a zero-config host still boots.
        var dsar = services.AddOptions<DsarOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
        if (configuration is not null)
        {
            dsar.Bind(configuration.GetSection(DsarOptions.SectionName));
        }

        // Bypass-path (cross-tenant control plane) slices.
        services.AddScoped<TenantProvisioner>();
        services.AddScoped<MembershipDirectory>();
        services.AddScoped<InvitationAcceptor>();
        services.AddScoped<ApiKeyResolver>();
        services.AddScoped<PlatformAdminDirectory>();
        services.AddScoped<PlatformAdminService>();
        services.AddScoped<ImpersonationGrantReader>();
        services.AddScoped<TenantSessionPolicyReader>();
        // Enterprise SSO (sso-and-scim.md sections 3, 4): the per-tenant config
        // reader and the JIT membership provisioner are cross-tenant bypass-path
        // slices (the caller holds no tid for the tenant yet), allowlisted by the
        // bypass-containment arch test.
        services.AddScoped<TenantSsoConfigReader>();
        services.AddScoped<SsoMembershipProvisioner>();

        // Request-path (RLS-bound) slices.
        services.AddScoped<TenantRoleResolver>();
        services.AddScoped<PermissionResolver>();
        services.AddScoped<CustomRoleService>();
        services.AddScoped<WorkspaceService>();
        services.AddScoped<TeamService>();
        services.AddScoped<ServiceAccountService>();
        services.AddScoped<TenantAdminService>();
        // The tenant-admin SSO config write path (settings:manage), RLS-bound, plus
        // the DataProtection protector for the write-only client secret (purpose
        // "identity.sso.client-secret.v1"; wraps the app-wide IDataProtectionProvider
        // registered by AddPlatformDataProtection, so it stays module-boundary clean).
        services.AddScoped<SsoConfigService>();
        services.AddScoped<SsoClientSecretProtector>();

        services.AddScoped<ITenancyApi, TenancyApi>();

        // DSAR contributors (data-export-and-erasure.md). Export contributors read the
        // request-scoped, RLS-bound TenancyDbContext (scoped, like the context); the
        // erasure contributor is a stateless table DECLARATION (singleton). Both are
        // declaration/read-only - the privileged erase runs in the allowlisted
        // PlatformAdminService, so this registration adds no bypass reach. Registered
        // in FK-safe export/aggregation order.
        services.AddScoped<IDataExportContributor, TenancyExportContributors.TenantProfile>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.Memberships>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.Workspaces>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.Teams>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.TeamMembers>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.Roles>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.RolePermissions>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.RoleAssignments>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.Invitations>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.ServiceAccounts>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.SsoConfiguration>();
        services.AddScoped<IDataExportContributor, TenancyExportContributors.SsoDomainClaims>();
        services.AddSingleton<ITenantErasureContributor, TenancyErasureContributor>();

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

        // Bridge the platform-declared session-policy port (used by the tid mint in
        // the Identity module's select-tenant endpoint and refresh handler) to the
        // bypass-path tenant reader, so Identity never references this module or the
        // tenancy.tenants table (role-templates-and-policy-defaults.md section 5).
        services.AddScoped<ITenantSessionPolicyReader>(
            provider => provider.GetRequiredService<TenantSessionPolicyReader>());

        // Bridge the platform-declared SSO ports (consumed by the Identity module's
        // OIDC flow) to the bypass-path Tenancy implementations, so Identity never
        // references this module or the tenancy.sso_* tables (sso-and-scim.md
        // sections 4, 7): the per-tenant config/domain reader and the JIT membership
        // provisioner.
        services.AddScoped<ITenantSsoConfigReader>(
            provider => provider.GetRequiredService<TenantSsoConfigReader>());
        services.AddScoped<ITenantSsoProvisioner>(
            provider => provider.GetRequiredService<SsoMembershipProvisioner>());

        return services;
    }
}
