using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "HMX_BY_MR_ARPIT_120";

string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
        .TrimEnd('/');

app.MapGet("/", () => "AuthServer API Service running");

/*
 REQUEST:
 {
   "id": "6282828",
   "hwid": "dhsf87yr28yhr2h",
   "session": "SESSION_TOKEN_FROM_LOGIN"
 }
*/
app.MapPost("/hmx/get-apis", async (HttpContext ctx) =>
{
    try
    {
        using var reader = new StreamReader(ctx.Request.Body);
        var body = JsonNode.Parse(await reader.ReadToEndAsync());
        if (body == null)
            return Results.BadRequest();

        string id = body["id"]!.GetValue<string>();
        string hwid = body["hwid"]!.GetValue<string>();
        string session = body["session"]!.GetValue<string>();

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // ---------- SESSION CHECK ----------
        var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
        if (sessionNode == null)
            return Results.Json(new { success = false, reason = "INVALID_SESSION" }, statusCode: 401);

        if (sessionNode["id"]!.GetValue<string>() != id ||
            sessionNode["hwid"]!.GetValue<string>() != hwid)
        {
            return Results.Json(new { success = false, reason = "SESSION_MISMATCH" }, statusCode: 401);
        }

        long expires = sessionNode["expires"]!.GetValue<long>();
        if (now > expires)
            return Results.Json(new { success = false, reason = "SESSION_EXPIRED" }, statusCode: 401);

        // ---------- USER ----------
        var user = await GetJson($"{firebaseDb}/users/{id}.json");
        if (user == null)
            return Results.Json(new { success = false, reason = "INVALID_USER" }, statusCode: 401);

        // ---------- APP FEATURES ----------
        var appCfg = await GetJson($"{firebaseDb}/app.json");
        var features = appCfg?["features"] as JsonObject ?? new JsonObject();

        var apiStore = await GetJson($"{firebaseDb}/apis.json");
        if (apiStore == null)
            return Results.Json(new { success = false, reason = "API_STORE_MISSING" }, statusCode: 500);

        var encryptedApis = new JsonObject();

        foreach (var feature in features)
        {
            string featureName = feature.Key;
            bool enabled = user[featureName]?.GetValue<bool>() ?? false;

            if (!enabled)
                continue;

            var apiGroup = apiStore[featureName] as JsonObject;
            if (apiGroup == null)
                continue;

            var encryptedGroup = new JsonObject();

            foreach (var api in apiGroup)
            {
                string apiUrl = api.Value!.GetValue<string>();

                // 🔐 Encrypt API per session + hwid
                string encrypted = EncryptApi(apiUrl, session, hwid);

                encryptedGroup[api.Key] = encrypted;
            }

            encryptedApis[featureName] = encryptedGroup;
        }

        return Results.Json(new
        {
            success = true,
            issued_at = now,
            ttl = 30, // seconds (client must respect)
            apis = encryptedApis
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message }, statusCode: 500);
    }
});

app.Run();


// ================= HELPERS =================

static string EncryptApi(string api, string session, string hwid)
{
    string keyMaterial = SECRET + session + hwid;
    byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(keyMaterial));

    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();

    using var encryptor = aes.CreateEncryptor();
    byte[] cipher = encryptor.TransformFinalBlock(
        Encoding.UTF8.GetBytes(api), 0, api.Length);

    return Convert.ToBase64String(aes.IV.Concat(cipher).ToArray());
}

static async Task<JsonNode?> GetJson(string url)
{
    using HttpClient http = new();
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode)
        return null;

    return JsonNode.Parse(await res.Content.ReadAsStringAsync());
}
