using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _25721 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string[]>(
                name: "saml_audiences",
                table: "application",
                type: "text[]",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "saml_encrypt",
                table: "application",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "saml_response_compress",
                table: "application",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$4U4QF19fvOA2aqRJcTEA3u51WXiKw84I0sjXcZQ4YNY8jTpA8Xl1G");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "saml_audiences",
                table: "application");

            migrationBuilder.DropColumn(
                name: "saml_encrypt",
                table: "application");

            migrationBuilder.DropColumn(
                name: "saml_response_compress",
                table: "application");

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$6zAIC1EWsrxlit65iwLlVez9zDjnWwE8A2RQt0Ob/OTLa/PRyP1Di");
        }
    }
}
