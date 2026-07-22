using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <inheritdoc />
    internal partial class SessionTenant : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "tenant_id",
                schema: "identity",
                table: "sessions",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "tenant_id",
                schema: "identity",
                table: "sessions");
        }
    }
}
