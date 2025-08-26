using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258161 : Migration
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
                    display_name = table.Column<string>(type: "text", nullable: false),
                    type = table.Column<string>(type: "text", nullable: false),
                    sub_type = table.Column<string>(type: "text", nullable: false),
                    favicon_url = table.Column<string>(type: "text", nullable: true),
                    client_id = table.Column<string>(type: "text", nullable: true),
                    client_secret = table.Column<string>(type: "text", nullable: true),
                    cert_id = table.Column<int>(type: "integer", nullable: true),
                    configure_url = table.Column<string>(type: "text", nullable: true),
                    auth_endpoint = table.Column<string>(type: "text", nullable: true),
                    token_endpoint = table.Column<string>(type: "text", nullable: true),
                    user_info_endpoint = table.Column<string>(type: "text", nullable: true),
                    jwks_endpoint = table.Column<string>(type: "text", nullable: true),
                    scopes = table.Column<string>(type: "text", nullable: true),
                    subject = table.Column<string>(type: "text", nullable: true),
                    body = table.Column<string>(type: "text", nullable: true),
                    enable_ssl = table.Column<bool>(type: "boolean", nullable: true),
                    port = table.Column<int>(type: "integer", nullable: true),
                    region_id = table.Column<string>(type: "text", nullable: true),
                    domain = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    user_info_map = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_provider", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "user_sessions",
                columns: table => new
                {
                    session_id = table.Column<string>(type: "text", nullable: false),
                    user_id = table.Column<string>(type: "text", nullable: false),
                    login_type = table.Column<string>(type: "text", nullable: false),
                    login_method = table.Column<string>(type: "text", nullable: false),
                    login_token = table.Column<string>(type: "text", nullable: false),
                    login_application = table.Column<string>(type: "text", nullable: false),
                    login_via = table.Column<string>(type: "text", nullable: false),
                    login_ip = table.Column<string>(type: "text", nullable: false),
                    expired_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_sessions", x => x.session_id);
                });

            migrationBuilder.CreateTable(
                name: "user_thirdpart_infos",
                columns: table => new
                {
                    provider_name = table.Column<string>(type: "text", nullable: false),
                    user_id = table.Column<string>(type: "text", nullable: false),
                    third_part_id = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_thirdpart_infos", x => new { x.provider_name, x.user_id });
                });

            migrationBuilder.CreateTable(
                name: "web_authn_credential",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    public_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    user_id = table.Column<string>(type: "text", nullable: false),
                    sign_count = table.Column<long>(type: "bigint", nullable: false),
                    transports = table.Column<int[]>(type: "integer[]", nullable: false),
                    is_backup_eligible = table.Column<bool>(type: "boolean", nullable: false),
                    is_backed_up = table.Column<bool>(type: "boolean", nullable: false),
                    attestation_object = table.Column<byte[]>(type: "bytea", nullable: true),
                    attestation_client_data_json = table.Column<byte[]>(type: "bytea", nullable: true),
                    reg_date = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    aa_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_web_authn_credential", x => x.id);
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
                    display_name = table.Column<string>(type: "text", nullable: false),
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
                        name: "fk_group_application_default_application_id",
                        column: x => x.default_application_id,
                        principalTable: "application",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "user",
                columns: table => new
                {
                    id = table.Column<string>(type: "text", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    roles = table.Column<string[]>(type: "text[]", nullable: false),
                    is_admin = table.Column<bool>(type: "boolean", nullable: false),
                    group_id = table.Column<int>(type: "integer", nullable: true),
                    email = table.Column<string>(type: "text", nullable: true),
                    email_verified = table.Column<bool>(type: "boolean", nullable: false),
                    phone = table.Column<string>(type: "text", nullable: true),
                    phone_verified = table.Column<bool>(type: "boolean", nullable: false),
                    password = table.Column<string>(type: "text", nullable: true),
                    preferred_mfa_type = table.Column<string>(type: "text", nullable: false),
                    totp_secret = table.Column<string>(type: "text", nullable: false),
                    enable_email_mfa = table.Column<bool>(type: "boolean", nullable: false),
                    enable_phone_mfa = table.Column<bool>(type: "boolean", nullable: false),
                    enable_totp_mfa = table.Column<bool>(type: "boolean", nullable: false),
                    recovery_code = table.Column<string>(type: "text", nullable: false),
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
                name: "ix_user_sessions_user_id",
                table: "user_sessions",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_user_thirdpart_infos_third_part_id",
                table: "user_thirdpart_infos",
                column: "third_part_id");

            migrationBuilder.CreateIndex(
                name: "ix_web_authn_credential_user_id",
                table: "web_authn_credential",
                column: "user_id");

            migrationBuilder.AddForeignKey(
                name: "fk_application_group_group_id",
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
                name: "fk_application_group_group_id",
                table: "application");

            migrationBuilder.DropTable(
                name: "provider");

            migrationBuilder.DropTable(
                name: "user");

            migrationBuilder.DropTable(
                name: "user_sessions");

            migrationBuilder.DropTable(
                name: "user_thirdpart_infos");

            migrationBuilder.DropTable(
                name: "web_authn_credential");

            migrationBuilder.DropTable(
                name: "cert");

            migrationBuilder.DropTable(
                name: "group");

            migrationBuilder.DropTable(
                name: "application");
        }
    }
}
