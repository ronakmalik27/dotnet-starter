using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Starter.Identity.Migrations
{
    /// <inheritdoc />
    internal partial class GoogleAuthLinking : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Preflight guard: narrowing to
            // varchar(255) would otherwise fail with an opaque Postgres
            // truncation error on any row already longer than that. This
            // is a pre-launch schema with no real production data yet
            // (Google's own `sub` claim is well under 255 chars by spec),
            // so a data-cleanup step is not warranted - just a loud,
            // diagnosable failure instead of Postgres's own, matching
            // this repo's fail-loud philosophy (e.g. Program.cs
            // config validation).
            migrationBuilder.Sql(
                """
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM identity.auth_methods
                        WHERE length(provider_subject) > 255
                    ) THEN
                        RAISE EXCEPTION
                            'GoogleAuthLinking migration: identity.auth_methods.provider_subject has a value longer than 255 characters; the varchar(255) narrowing would truncate it. Clean up the offending row(s) before re-running this migration.';
                    END IF;
                END $$;
                """);

            migrationBuilder.AlterColumn<string>(
                name: "provider_subject",
                schema: "identity",
                table: "auth_methods",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "disabled_at",
                schema: "identity",
                table: "auth_methods",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "disabled_at",
                schema: "identity",
                table: "auth_methods");

            migrationBuilder.AlterColumn<string>(
                name: "provider_subject",
                schema: "identity",
                table: "auth_methods",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(255)",
                oldMaxLength: 255,
                oldNullable: true);
        }
    }
}
