using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ====== app ======
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ====== helpers ======
string PemEncode(string label, byte[] data)
{
    var b64 = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
    return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----";
}

string Sha256(string s)
{
    using var sha = SHA256.Create();
    var h = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
    return Convert.ToHexString(h);
}

string? ReadAdminHeader(HttpContext ctx)
{
    // aceita variações comuns do cabeçalho
    string[] keys = { "Admin-API-Key", "admin-api-key", "X-Admin-API-Key" };
    foreach (var k in keys)
    {
        if (ctx.Request.Headers.TryGetValue(k, out var v))
        {
            var val = v.ToString().Trim();
            // remove aspas acidentais
            if (val.StartsWith("\"") && val.EndsWith("\"") && val.Length >= 2)
                val = val.Substring(1, val.Length - 2);
            return val;
        }
    }
    return null;
}

string ReadAdminFromEnv()
{
    var envVal = Environment.GetEnvironmentVariable("Admin-API-Key");
    if (string.IsNullOrWhiteSpace(envVal)) envVal = "CHANGEME";
    envVal = envVal.Trim();
    if (envVal.StartsWith("\"") && envVal.EndsWith("\"") && envVal.Length >= 2)
        envVal = envVal.Substring(1, envVal.Length - 2);
    return envVal;
}

// ====== keys (PRIVATE -> PUBLIC) ======
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

// ====== endpoints ======
app.MapGet("/", () => Results.Json(new
{
    ok = true,
    service = "DriveBackupPro.LicenseServer",
    endpoints = new[] { "/healthz", "/api/public-key", "POST /api/license", "/debug/admin", "/debug/headers" }
}));

app.MapGet("/healthz", () => Results.Ok("ok"));
app.MapGet("/api/public-key", () => Results.Text(publicPem, "text/plain"));

// ---- DEBUG seguro (remova depois que ajustar 401) ----
app.MapGet("/debug/admin", () =>
{
    var expected = ReadAdminFromEnv();
    return Results.Json(new
    {
        hasEnv = !string.IsNullOrWhiteSpace(expected),
        envLen = expected.Length,
        envSha256 = Sha256(expected),
        note = "Compare com /debug/headers. Mostrando apenas hash e tamanho por segurança."
    });
});

app.MapGet("/debug/headers", (HttpContext ctx) =>
{
    var received = ReadAdminHeader(ctx);
    return Results.Json(new
    {
        sawHeader = received != null,
        headerLen = received?.Length ?? 0,
        headerSha256 = received != null ? Sha256(received) : null,
        note = "Mostrando apenas hash e tamanho por segurança."
    });
});
// ---- FIM DEBUG ----

app.MapPost("/api/license", async (HttpContext ctx) =>
{
    // 1) valida Admin-API-Key
    var expected = ReadAdminFromEnv();
    var received = ReadAdminHeader(ctx);

    if (string.IsNullOrEmpty(received) ||
        !string.Equals(received, expected, StringComparison.Ordinal))
    {
        app.Logger.LogWarning("401 Unauthorized: headerSha={headerSha} headerLen={headerLen} envSha={envSha} envLen={envLen}",
            received != null ? Sha256(received) : "null",
            received?.Length ?? 0,
            Sha256(expected),
            expected.Length
        );
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

    // 3) payload que o cliente espera
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

// ====== records (tipos) — nada de statements depois daqui! ======
public record LicenseRequest(string machineId, int months);
public record LicensePayload(string MachineId, string IssuedUtc, string ExpiresUtc, string Type);
