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
            migrationBuilder.CreateTable(
                name: "cert",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "text", nullable: false),
                    type = table.Column<string>(type: "text", nullable: false),
                    bit_size = table.Column<int>(type: "integer", nullable: false),
                    crypto_algorithm = table.Column<string>(type: "text", nullable: false),
                    crypto_sha_size = table.Column<int>(type: "integer", nullable: false),
                    certificate = table.Column<string>(type: "text", nullable: true),
                    privite_key = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_cert", x => x.id);
                });

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

            migrationBuilder.CreateTable(
                name: "application",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "text", nullable: false),
                    client_id = table.Column<string>(type: "text", nullable: false),
                    client_secret = table.Column<string>(type: "text", nullable: false),
                    scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    cert_id = table.Column<int>(type: "integer", nullable: false),
                    group_id = table.Column<int>(type: "integer", nullable: false),
                    redirect_urls = table.Column<string[]>(type: "text[]", nullable: true),
                    expired_second = table.Column<int>(type: "integer", nullable: false),
                    saml_audiences = table.Column<string[]>(type: "text[]", nullable: true),
                    saml_response_compress = table.Column<bool>(type: "boolean", nullable: false),
                    saml_encrypt = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    provider_items = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_application", x => x.id);
                    table.ForeignKey(
                        name: "fk_application_cert_cert_id",
                        column: x => x.cert_id,
                        principalTable: "cert",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "group",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "text", nullable: false),
                    default_roles = table.Column<string[]>(type: "text[]", nullable: false),
                    parent_id = table.Column<int>(type: "integer", nullable: false),
                    parent_chain = table.Column<string>(type: "text", nullable: false),
                    top_id = table.Column<int>(type: "integer", nullable: true),
                    default_application_id = table.Column<int>(type: "integer", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_group", x => x.id);
                    table.ForeignKey(
                        name: "fk_default_application",
                        column: x => x.default_application_id,
                        principalTable: "application",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "user",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "text", nullable: false),
                    number = table.Column<string>(type: "text", nullable: false),
                    roles = table.Column<string[]>(type: "text[]", nullable: false),
                    group_id = table.Column<int>(type: "integer", nullable: true),
                    email = table.Column<string>(type: "text", nullable: true),
                    email_verified = table.Column<bool>(type: "boolean", nullable: false),
                    phone = table.Column<string>(type: "text", nullable: true),
                    phone_verified = table.Column<bool>(type: "boolean", nullable: false),
                    password = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user", x => x.id);
                    table.ForeignKey(
                        name: "fk_user_group_group_id",
                        column: x => x.group_id,
                        principalTable: "group",
                        principalColumn: "id");
                });

            migrationBuilder.CreateIndex(
                name: "ix_application_cert_id",
                table: "application",
                column: "cert_id");

            migrationBuilder.CreateIndex(
                name: "ix_application_client_id",
                table: "application",
                column: "client_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_application_group_id",
                table: "application",
                column: "group_id");

            migrationBuilder.CreateIndex(
                name: "ix_cert_name",
                table: "cert",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_group_default_application_id",
                table: "group",
                column: "default_application_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_group_name",
                table: "group",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_provider_name",
                table: "provider",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_user_group_id",
                table: "user",
                column: "group_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_number",
                table: "user",
                column: "number",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "fk_parent_group",
                table: "application",
                column: "group_id",
                principalTable: "group",
                principalColumn: "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_application_cert_cert_id",
                table: "application");

            migrationBuilder.DropForeignKey(
                name: "fk_parent_group",
                table: "application");

            migrationBuilder.DropTable(
                name: "provider");

            migrationBuilder.DropTable(
                name: "user");

            migrationBuilder.DropTable(
                name: "cert");

            migrationBuilder.DropTable(
                name: "group");

            migrationBuilder.DropTable(
                name: "application");
        }
    }
}
