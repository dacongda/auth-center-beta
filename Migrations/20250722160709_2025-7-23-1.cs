using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20257231 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "provider_items",
                table: "application",
                type: "jsonb",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "provider",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "text", nullable: false),
                    type = table.Column<string>(type: "text", nullable: false),
                    sub_type = table.Column<string>(type: "text", nullable: false),
                    favicon_url = table.Column<string>(type: "text", nullable: true),
                    client_id = table.Column<string>(type: "text", nullable: true),
                    client_secret = table.Column<string>(type: "text", nullable: true),
                    cert_id = table.Column<int>(type: "integer", nullable: true),
                    configure_url = table.Column<string>(type: "text", nullable: true),
                    subject = table.Column<string>(type: "text", nullable: true),
                    body = table.Column<string>(type: "text", nullable: true),
                    enable_ssl = table.Column<bool>(type: "boolean", nullable: true),
                    port = table.Column<int>(type: "integer", nullable: true),
                    region_id = table.Column<string>(type: "text", nullable: true),
                    domain = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_provider", x => x.id);
                });

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$9.tkv.EXpsA02Pe.wOOmReXLZ3vabZeOV3Z1JPIDGTvsWtghy6pxG");

            migrationBuilder.CreateIndex(
                name: "ix_provider_name",
                table: "provider",
                column: "name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "provider");

            migrationBuilder.DropColumn(
                name: "provider_items",
                table: "application");

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$4U4QF19fvOA2aqRJcTEA3u51WXiKw84I0sjXcZQ4YNY8jTpA8Xl1G");
        }
    }
}
