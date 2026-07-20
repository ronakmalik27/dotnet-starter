using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;

namespace Starter.Platform.Data;

/// <summary>
/// Guid primary keys are never database-generated: the app mints UUIDv7
/// values through the SharedKernel Ids helper. This
/// convention makes that the default for every entity in every module, so
/// no per-entity configuration can silently fall back to a database
/// default or a v4 generator.
/// </summary>
public sealed class AppSideKeyConvention : IModelFinalizingConvention
{
    public void ProcessModelFinalizing(
        IConventionModelBuilder modelBuilder,
        IConventionContext<IConventionModelBuilder> context)
    {
        foreach (var entityType in modelBuilder.Metadata.GetEntityTypes())
        {
            var key = entityType.FindPrimaryKey();
            if (key is null)
            {
                continue;
            }

            foreach (var property in key.Properties)
            {
                if (property.ClrType == typeof(Guid))
                {
                    // Builder is null when the property has left the model.
                    property.Builder?.ValueGenerated(ValueGenerated.Never);
                }
            }
        }
    }
}
