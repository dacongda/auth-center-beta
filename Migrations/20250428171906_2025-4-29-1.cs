using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20254291 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                columns: new[] { "password", "roles" },
                values: new object[] { "$2a$11$PSFf7z1DPyvqnmrag73mUOz7cT2VW8TiufYgUIKEc/aYh8Xnx7vAy", new[] { "admin" } });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                columns: new[] { "password", "roles" },
                values: new object[] { "$2a$11$Rxv/Sw/QkvLe7/zazUWItuZ7OZOnNLf7UOcJQ3OXUMbXPhfNalprm", new string[0] });
        }
    }
}
