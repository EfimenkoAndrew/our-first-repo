// ============================================================================
// INTENTIONALLY VULNERABLE CODE — FOR CODEQL / SAST DEMONSTRATION ONLY.
//
// Every endpoint in this file deliberately reproduces a well-known
// vulnerability class so that CodeQL (or another static analyzer) has real
// findings to detect in this repo. Do NOT copy these patterns into real
// application code, and do NOT deploy this file to any environment that
// isn't a private, disposable learning/scanning sandbox.
// ============================================================================

using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;

namespace WebApplication1.CodeQlExamples;

public static class VulnerableEndpoints
{
    // CWE-798: Hardcoded credentials. CodeQL: cs/hardcoded-credentials
    private const string ConnectionString =
        "Server=localhost;Database=Demo;User Id=sa;Password=P@ssw0rd123!;";

    public static void MapVulnerableExamples(this WebApplication app)
    {
        var group = app.MapGroup("/codeql-examples").WithTags("CodeQL Examples (intentionally vulnerable)");

        // CWE-89: SQL Injection via string concatenation.
        // CodeQL: cs/sql-injection
        group.MapGet("/sql-injection", async (string username) =>
        {
            await using var connection = new SqlConnection(ConnectionString);
            await connection.OpenAsync();

            var query = "SELECT * FROM Users WHERE Username = '" + username + "'";
            await using var command = new SqlCommand(query, connection);
            await using var reader = await command.ExecuteReaderAsync();

            var results = new List<string>();
            while (await reader.ReadAsync())
            {
                results.Add(reader.GetString(0));
            }

            return Results.Ok(results);
        });

        // CWE-79: Reflected XSS — user input written directly into an HTML response.
        // CodeQL: cs/web/xss
        group.MapGet("/xss", (string name) =>
        {
            var html = $"<html><body><h1>Welcome, {name}!</h1></body></html>";
            return Results.Content(html, "text/html");
        });

        // CWE-78: OS Command Injection — user input passed straight to a shell.
        // CodeQL: cs/command-line-injection
        group.MapGet("/command-injection", (string host) =>
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"ping -c 1 {host}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };

            using var process = Process.Start(psi);
            var output = process?.StandardOutput.ReadToEnd();
            return Results.Ok(output);
        });

        // CWE-22: Path Traversal — user input used to build a file path with no sanitization.
        // CodeQL: cs/path-injection
        group.MapGet("/path-traversal", (string fileName) =>
        {
            var basePath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
            var fullPath = Path.Combine(basePath, fileName);
            var content = File.ReadAllText(fullPath);
            return Results.Text(content);
        });

        // CWE-918: Server-Side Request Forgery — user-supplied URL fetched server-side.
        // CodeQL: cs/server-side-request-forgery
        group.MapGet("/ssrf", async (string url) =>
        {
            using var httpClient = new HttpClient();
            var response = await httpClient.GetStringAsync(url);
            return Results.Ok(response);
        });

        // CWE-601: Open Redirect — user-supplied URL used as a redirect target.
        // CodeQL: cs/web/unvalidated-url-redirection
        group.MapGet("/open-redirect", (string returnUrl) => Results.Redirect(returnUrl));

        // CWE-502: Insecure Deserialization — TypeNameHandling.All lets the payload
        // control which .NET type gets instantiated.
        // CodeQL: cs/unsafe-deserialization
        group.MapPost("/insecure-deserialization", (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var json = reader.ReadToEnd();
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Results.Ok(obj);
        });

        // CWE-327 / CWE-916: Weak/broken hashing algorithm used for password storage,
        // with no salt.
        // CodeQL: cs/weak-sensitive-data-hashing
        group.MapGet("/weak-crypto", (string password) =>
        {
            using var md5 = MD5.Create();
            var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return Results.Ok(Convert.ToHexString(hash));
        });

        // CWE-338: Cryptographically weak PRNG used to generate a security token.
        // CodeQL: cs/insecure-randomness
        group.MapGet("/insecure-randomness", () =>
        {
            var token = new Random().Next(100000, 999999).ToString();
            return Results.Ok(new { token });
        });
    }
}
