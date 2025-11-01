using System.Security.Cryptography;
using System.Text;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var keyDir = Path.Combine(AppContext.BaseDirectory, "keys");
Directory.CreateDirectory(keyDir);
var privPath = Path.Combine(keyDir, "private.pem");
var pubPath = Path.Combine(keyDir, "public.pem");

if (!File.Exists(privPath) || !File.Exists(pubPath))
{
    using var rsa = RSA.Create(2048);
    var priv = rsa.ExportPkcs8PrivateKey();
    var pub = rsa.ExportSubjectPublicKeyInfo();
    File.WriteAllText(privPath, PemEncode("PRIVATE KEY", priv));
    File.WriteAllText(pubPath, PemEncode("PUBLIC KEY", pub));
}

app.MapGet("/healthz", () => Results.Ok("ok"));
app.MapGet("/api/public-key", () => Results.Text(File.ReadAllText(pubPath), "text/plain"));

app.MapPost("/api/license", async (HttpContext ctx) =>
{
    // Lê do ambiente (Render → Settings → Environment → Admin-API-Key)
    var admin = Environment.GetEnvironmentVariable("Admin-API-Key") ?? "CHANGEME";

    if (!ctx.Request.Headers.TryGetValue("Admin-API-Key", out var hk) ||
        !string.Equals(hk.ToString().Trim(), admin.Trim(), StringComparison.Ordinal))
    {
        return Results.Unauthorized();
    }

    using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync(); // JSON com machineId/months

    // ... assina com a PRIVATE e retorna { token }
    var bytes = Encoding.UTF8.GetBytes(body);
    using var privateRsa = RSA.Create();

    // Se você usa PRIVATE_PEM como secret no Render, importe aqui:
    var envPriv = Environment.GetEnvironmentVariable("PRIVATE_PEM");
    if (!string.IsNullOrWhiteSpace(envPriv))
        privateRsa.ImportFromPem(envPriv);
    else
        privateRsa.ImportFromPem(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "keys", "private.pem")));

    var sig = privateRsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var token = Convert.ToBase64String(bytes) + "." + Convert.ToBase64String(sig);

    return Results.Json(new { token });
});


app.Run();

static string PemEncode(string label, byte[] data)
{
    var b64 = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
    return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----";
}
