using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCenter.Migrations
{
    /// <inheritdoc />
    public partial class _20258164 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_application_group_group_id",
                table: "application");

            migrationBuilder.DropIndex(
                name: "ix_application_group_id",
                table: "application");

            migrationBuilder.RenameColumn(
                name: "group_id",
                table: "application",
                newName: "access_expired_second");

            migrationBuilder.AlterColumn<string[]>(
                name: "saml_audiences",
                table: "application",
                type: "text[]",
                nullable: false,
                defaultValue: new string[0],
                oldClrType: typeof(string[]),
                oldType: "text[]",
                oldNullable: true);

            migrationBuilder.AddColumn<int[]>(
                name: "group_ids",
                table: "application",
                type: "integer[]",
                nullable: false,
                defaultValue: new int[0]);

            migrationBuilder.CreateIndex(
                name: "ix_user_email",
                table: "user",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_user_phone",
                table: "user",
                column: "phone",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_user_email",
                table: "user");

            migrationBuilder.DropIndex(
                name: "ix_user_phone",
                table: "user");

            migrationBuilder.DropColumn(
                name: "group_ids",
                table: "application");

            migrationBuilder.RenameColumn(
                name: "access_expired_second",
                table: "application",
                newName: "group_id");

            migrationBuilder.AlterColumn<string[]>(
                name: "saml_audiences",
                table: "application",
                type: "text[]",
                nullable: true,
                oldClrType: typeof(string[]),
                oldType: "text[]");

            migrationBuilder.CreateIndex(
                name: "ix_application_group_id",
                table: "application",
                column: "group_id");

            migrationBuilder.AddForeignKey(
                name: "fk_application_group_group_id",
                table: "application",
                column: "group_id",
                principalTable: "group",
                principalColumn: "id");
        }
    }
}
