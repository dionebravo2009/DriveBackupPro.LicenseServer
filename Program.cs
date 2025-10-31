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
    if (!ctx.Request.Headers.TryGetValue("Admin-API-Key", out var k) || k != "CHANGEME")
        return Results.Unauthorized();
    using var reader = new StreamReader(ctx.Request.Body);
    var json = await reader.ReadToEndAsync();
    var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText(privPath));
    var bytes = Encoding.UTF8.GetBytes(json);
    var sig = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var token = Convert.ToBase64String(bytes) + "." + Convert.ToBase64String(sig);
    return Results.Json(new { token });
});

app.Run();

static string PemEncode(string label, byte[] data)
{
    var b64 = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
    return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----";
}
