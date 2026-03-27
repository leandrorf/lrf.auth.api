using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace lrf.auth.api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddOAuthPkce : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Remove vestígio de aplicação parcial anterior (tabelas sem índice / migração não registrada).
            migrationBuilder.Sql("DROP TABLE IF EXISTS oauth_client_redirect_uris;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS oauth_authorization_codes;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS oauth_clients;");

            migrationBuilder.CreateTable(
                name: "oauth_authorization_codes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    CodeHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    ClientId = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RedirectUri = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CodeChallenge = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CodeChallengeMethod = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Scope = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Nonce = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Consumed = table.Column<bool>(type: "tinyint(1)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_authorization_codes", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "oauth_clients",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RequirePkce = table.Column<bool>(type: "tinyint(1)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_clients", x => x.ClientId);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "oauth_client_redirect_uris",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    ClientId = table.Column<string>(type: "varchar(64)", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RedirectUri = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_client_redirect_uris", x => x.Id);
                    table.ForeignKey(
                        name: "FK_oauth_client_redirect_uris_oauth_clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "oauth_clients",
                        principalColumn: "ClientId",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_oauth_authorization_codes_CodeHash",
                table: "oauth_authorization_codes",
                column: "CodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oauth_client_redirect_uris_ClientId_RedirectUri",
                table: "oauth_client_redirect_uris",
                columns: new[] { "ClientId", "RedirectUri" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "oauth_authorization_codes");

            migrationBuilder.DropTable(
                name: "oauth_client_redirect_uris");

            migrationBuilder.DropTable(
                name: "oauth_clients");
        }
    }
}
