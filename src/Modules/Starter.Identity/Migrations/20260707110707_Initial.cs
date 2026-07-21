using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <inheritdoc />
    internal partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The module owns its schema: never rely on the provider's
            // history repository creating it as a side effect.
            migrationBuilder.EnsureSchema(name: "identity");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Intentionally forward-only: the initial schema is the baseline
            // and is never rolled back below it (dropping the schema would
            // take every later migration's tables with it).
        }
    }
}
