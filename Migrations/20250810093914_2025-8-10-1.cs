using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258101 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "auth_endpoint",
                table: "provider",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "jwks_endpoint",
                table: "provider",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "scopes",
                table: "provider",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "token_endpoint",
                table: "provider",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "user_info_endpoint",
                table: "provider",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "user_info_map",
                table: "provider",
                type: "jsonb",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "auth_endpoint",
                table: "provider");

            migrationBuilder.DropColumn(
                name: "jwks_endpoint",
                table: "provider");

            migrationBuilder.DropColumn(
                name: "scopes",
                table: "provider");

            migrationBuilder.DropColumn(
                name: "token_endpoint",
                table: "provider");

            migrationBuilder.DropColumn(
                name: "user_info_endpoint",
                table: "provider");

            migrationBuilder.DropColumn(
                name: "user_info_map",
                table: "provider");
        }
    }
}
