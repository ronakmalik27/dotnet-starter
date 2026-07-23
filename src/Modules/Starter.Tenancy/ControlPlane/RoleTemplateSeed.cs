namespace Starter.Tenancy.ControlPlane;

/// <summary>
/// The seed-relevant projection of a <c>platform.role_templates</c> row
/// (role-templates-and-policy-defaults.md section 2), read on the bypass connection
/// by the provisioner (at signup) and the super-admin bulk-seed. It carries exactly
/// the fields needed to insert one tenant custom role: the stable
/// <paramref name="Key"/> (stamped onto the seeded role's template_key), the
/// <paramref name="Name"/> and <paramref name="Description"/>, the closed
/// <paramref name="Permissions"/> set (filtered to the plan-allowed subset at seed
/// time), and the <paramref name="AssignableScopes"/> that map to the role's
/// assignable_at.
/// </summary>
internal sealed record RoleTemplateSeed(
    string Key,
    string Name,
    string Description,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> AssignableScopes);
