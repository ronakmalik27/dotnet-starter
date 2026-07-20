using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Starter.Platform.Data;

namespace Starter.Platform.DataProtection;

/// <summary>
/// Wires ASP.NET DataProtection to persist its key ring in the platform
/// DbContext. This must live inside the Platform assembly: PlatformDbContext
/// is internal, so the composition root cannot name it for
/// PersistKeysToDbContext itself - this public method is the seam.
///
/// The application name pins the key-derivation purpose so every replica
/// (and every restart) shares one ring. Nothing consumes DataProtection in
/// the template yet; this is the forward-looking default so the first
/// DP-dependent feature added later inherits durable, shared keys rather
/// than filesystem keys that vanish on restart.
/// </summary>
public static class PlatformDataProtection
{
    public static IServiceCollection AddPlatformDataProtection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddDataProtection()
            .SetApplicationName("Starter")
            .PersistKeysToDbContext<PlatformDbContext>();

        return services;
    }
}
