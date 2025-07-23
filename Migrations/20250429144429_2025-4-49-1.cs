using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20254491 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$8GRleU0bQK5ipyTUFJ8lSeG8dZy7nhNETiTOrKvQ6ji/pzWBfzROu");

            migrationBuilder.CreateIndex(
                name: "ix_application_cert_id",
                table: "application",
                column: "cert_id");

            migrationBuilder.AddForeignKey(
                name: "fk_application_cert_cert_id",
                table: "application",
                column: "cert_id",
                principalTable: "cert",
                principalColumn: "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_application_cert_cert_id",
                table: "application");

            migrationBuilder.DropIndex(
                name: "ix_application_cert_id",
                table: "application");

            migrationBuilder.UpdateData(
                table: "user",
                keyColumn: "id",
                keyValue: 1,
                column: "password",
                value: "$2a$11$PSFf7z1DPyvqnmrag73mUOz7cT2VW8TiufYgUIKEc/aYh8Xnx7vAy");
        }
    }
}
