using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Tenancy.Migrations
{
    /// <summary>
    /// ABAC conditional grants (abac.md sections 2, 11): adds a nullable
    /// condition jsonb column to tenancy.role_assignments. NULL = unconditional
    /// (every existing grant), so there is no data backfill and no index change -
    /// the two partial unique indexes are UNCHANGED (a condition is an attribute OF
    /// a grant, not a way to hold the same role twice at one scope). The column
    /// inherits the table's existing fail-closed RLS + FORCE policy, so nothing new
    /// is needed at the policy level; Postgres validates it is well-formed JSON and
    /// the evaluator owns its semantics.
    /// </summary>
    /// <inheritdoc />
    internal partial class AbacConditionalGrant : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "condition",
                schema: "tenancy",
                table: "role_assignments",
                type: "jsonb",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "condition",
                schema: "tenancy",
                table: "role_assignments");
        }
    }
}
