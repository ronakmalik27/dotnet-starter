using System.Collections.Frozen;
using System.Reflection;
using System.Text;
using Starter.Platform.Tenancy;

namespace Starter.Platform.Dsar;

/// <summary>
/// Resolves the set of database column names that carry a <see cref="SensitiveAttribute"/>
/// on some <see cref="ITenantOwned"/> type (data-export-and-erasure.md section 8). It
/// is the reflection half of the secret-exclusion completeness mechanism: the operator
/// snapshot redacts exactly this set, so a new secret column is redacted the moment its
/// property is annotated - never by remembering to update a list.
/// <para>
/// The column name is the snake_case of the property name, matching
/// <c>UseSnakeCaseNamingConvention</c> (the one place EF maps names), so the redaction
/// set aligns with the raw <c>select *</c> column names the snapshot reads.
/// </para>
/// </summary>
public static class SensitiveColumns
{
    /// <summary>
    /// The snake_case column names of every <see cref="SensitiveAttribute"/>-marked
    /// property on an <see cref="ITenantOwned"/> type in <paramref name="assemblies"/>.
    /// </summary>
    public static FrozenSet<string> From(IEnumerable<Assembly> assemblies)
    {
        ArgumentNullException.ThrowIfNull(assemblies);

        var columns = new HashSet<string>(StringComparer.Ordinal);
        foreach (var assembly in assemblies.Distinct())
        {
            foreach (var type in assembly.GetTypes())
            {
                if (!typeof(ITenantOwned).IsAssignableFrom(type) || type.IsInterface || type.IsAbstract)
                {
                    continue;
                }

                foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (property.GetCustomAttribute<SensitiveAttribute>() is not null)
                    {
                        columns.Add(ToSnakeCase(property.Name));
                    }
                }
            }
        }

        return columns.ToFrozenSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// PascalCase to snake_case, the <c>UseSnakeCaseNamingConvention</c> mapping for the
    /// simple identifiers here (<c>KeyHash</c> -&gt; <c>key_hash</c>,
    /// <c>SigningSecretEncrypted</c> -&gt; <c>signing_secret_encrypted</c>).
    /// </summary>
    private static string ToSnakeCase(string name)
    {
        var builder = new StringBuilder(name.Length + 8);
        for (var index = 0; index < name.Length; index++)
        {
            var character = name[index];
            if (char.IsUpper(character))
            {
                if (index > 0)
                {
                    builder.Append('_');
                }

                builder.Append(char.ToLowerInvariant(character));
            }
            else
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }
}
