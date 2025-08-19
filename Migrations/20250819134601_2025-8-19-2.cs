using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258192 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "saml_attributes",
                table: "application",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "saml_redirects",
                table: "application",
                type: "jsonb",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "saml_attributes",
                table: "application");

            migrationBuilder.DropColumn(
                name: "saml_redirects",
                table: "application");
        }
    }
}
