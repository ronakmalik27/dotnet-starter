using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Platform.Migrations
{
    /// <inheritdoc />
    internal partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The module owns its schema: never rely on the provider's
            // history repository creating it as a side effect.
            migrationBuilder.EnsureSchema(name: "platform");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
