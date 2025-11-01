using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ===== util =====
string PemEncode(string label, byte[] data)
{
    var b64 = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
    return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----";
}

// ===== carrega/gera chaves =====
RSA privateRsa;
string publicPem;

var envPriv = Environment.GetEnvironmentVariable("PRIVATE_PEM");
if (!string.IsNullOrWhiteSpace(envPriv))
{
    privateRsa = RSA.Create();
    privateRsa.ImportFromPem(envPriv);

    using var pubTmp = RSA.Create();
    pubTmp.ImportRSAPublicKey(privateRsa.ExportRSAPublicKey(), out _);
    publicPem = PemEncode("PUBLIC KEY", pubTmp.ExportSubjectPublicKeyInfo());
}
else
{
    var keyDir = Path.Combine(AppContext.BaseDirectory, "keys");
    Directory.CreateDirectory(keyDir);
    var privPath = Path.Combine(keyDir, "private.pem");
    var pubPath  = Path.Combine(keyDir, "public.pem");

    if (!File.Exists(privPath) || !File.Exists(pubPath))
    {
        using var gen = RSA.Create(2048);
        File.WriteAllText(privPath, PemEncode("PRIVATE KEY", gen.ExportPkcs8PrivateKey()));
        File.WriteAllText(pubPath,  PemEncode("PUBLIC KEY",  gen.ExportSubjectPublicKeyInfo()));
    }

    privateRsa = RSA.Create();
    privateRsa.ImportFromPem(File.ReadAllText(privPath));
    publicPem = File.ReadAllText(pubPath);
}

// ===== endpoints =====
app.MapGet("/", () => Results.Json(new
{
    ok = true,
    service = "DriveBackupPro.LicenseServer",
    endpoints = new[] { "/healthz", "/api/public-key", "POST /api/license" }
}));

app.MapGet("/healthz", () => Results.Ok("ok"));
app.MapGet("/api/public-key", () => Results.Text(publicPem, "text/plain"));

app.MapPost("/api/license", async (HttpContext ctx) =>
{
    // 1) valida cabeçalho Admin-API-Key
    var admin = Environment.GetEnvironmentVariable("Admin-API-Key") ?? "CHANGEME";
    if (!ctx.Request.Headers.TryGetValue("Admin-API-Key", out var hk) ||
        !string.Equals(hk.ToString().Trim(), admin.Trim(), StringComparison.Ordinal))
    {
        return Results.Unauthorized();
    }

    // 2) body: { "machineId": "...", "months": 1 }
    LicenseRequest req;
    try
    {
        req = await ctx.Request.ReadFromJsonAsync<LicenseRequest>() 
              ?? throw new Exception("JSON inválido");
        if (string.IsNullOrWhiteSpace(req.machineId) || req.months <= 0)
            throw new Exception("machineId ou months inválidos");
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "Bad JSON: " + ex.Message });
    }

    // 3) payload compatível com o cliente WPF
    var issued  = DateTime.UtcNow;
    var expires = issued.AddMonths(req.months);
    var payload = new LicensePayload(
        MachineId: req.machineId,
        IssuedUtc: issued.ToString("o"),
        ExpiresUtc: expires.ToString("o"),
        Type: "monthly"
    );

    var json = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions
    {
        PropertyNamingPolicy = null,
        WriteIndented = false
    });

    // 4) assina com RSA-SHA256 (PKCS#1 v1.5)
    var sig = privateRsa.SignData(json, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    // 5) token = base64(payloadJson) + "." + base64(signature)
    var token = Convert.ToBase64String(json) + "." + Convert.ToBase64String(sig);
    return Results.Json(new { token });
});

app.Run();

// ===== Tipos (apenas no final; NENHUM statement depois disso) =====
public record LicenseRequest(string machineId, int months);
public record LicensePayload(string MachineId, string IssuedUtc, string ExpiresUtc, string Type);
