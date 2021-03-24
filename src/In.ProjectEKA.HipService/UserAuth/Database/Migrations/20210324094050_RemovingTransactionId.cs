using Microsoft.EntityFrameworkCore.Migrations;

namespace In.ProjectEKA.HipService.Migrations
{
    public partial class RemovingTransactionId : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm");

            migrationBuilder.DropColumn(
                name: "TransactionId",
                table: "AuthConfirm");

            migrationBuilder.AlterColumn<string>(
                name: "HealthId",
                table: "AuthConfirm",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm",
                column: "HealthId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm");

            migrationBuilder.AlterColumn<string>(
                name: "HealthId",
                table: "AuthConfirm",
                type: "text",
                nullable: true,
                oldClrType: typeof(string));

            migrationBuilder.AddColumn<string>(
                name: "TransactionId",
                table: "AuthConfirm",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_AuthConfirm",
                table: "AuthConfirm",
                column: "TransactionId");
        }
    }
}
