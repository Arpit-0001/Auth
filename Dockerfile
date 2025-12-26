using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "HMX_BY_MR_ARPIT_120";

string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
    .TrimEnd('/');

HttpClient http = new HttpClient();

app.MapGet("/", () => "AuthServer running");

app.MapPost("/hmx/oauth", async (HttpContext ctx) =>
{
    try
    {
        var body = await JsonNode.ParseAsync(ctx.Request.Body);
        if (body == null)
            return Results.BadRequest(new { success = false });

        string id = body["id"]!.GetValue<string>();
        string hwid = body["hwid"]!.GetValue<string>();
        string version = body["version"]!.GetValue<string>();
        string nonce = body["nonce"]!.GetValue<string>();
        string sig = body["sig"]!.GetValue<string>();

        // ---------------- HMAC VERIFY ----------------
        string raw = id + hwid + version + nonce;
        string expectedSig = ComputeHmac(raw);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(sig),
                Encoding.UTF8.GetBytes(expectedSig)))
        {
            return Results.Unauthorized(new
            {
                success = false,
                reason = "INVALID_SIGNATURE"
            });
        }

        // ---------------- APP VERSION ----------------
        JsonNode appCfg =
            await GetJson($"{firebaseDb}/app.json");

        string serverVersion =
            appCfg["version"]!.GetValue<double>().ToString("0.0.0");

        if (version != serverVersion)
        {
            return Results.StatusCode(426,
                new
                {
                    success = false,
                    reason = "UPDATE_REQUIRED",
                    requiredVersion = serverVersion
                });
        }

        // ---------------- USER ----------------
        JsonNode user =
            await GetJson($"{firebaseDb}/users/{id}.json");

        if (user == null)
        {
            await RegisterFail(hwid);
            return Results.Unauthorized(new
            {
                success = false,
                reason = "INVALID_USER"
            });
        }

        // ---------------- HWID BAN ----------------
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        JsonNode attempt =
            await GetJson($"{firebaseDb}/hwid_attempts/{hwid}.json");

        int count = attempt?["count"]?.GetValue<int>() ?? 0;
        long banUntil = attempt?["banUntil"]?.GetValue<long>() ?? 0;

        if (banUntil > now)
        {
            return Results.StatusCode(403, new
            {
                success = false,
                reason = "HWID_BANNED",
                retryAfter = banUntil - now
            });
        }

        if (count >= 3)
        {
            long ban = now + 86400;
            await PutJson(
                $"{firebaseDb}/hwid_attempts/{hwid}.json",
                JsonNode.Parse($$"""
                {
                    "count": {{count}},
                    "lastFail": {{now}},
                    "banUntil": {{ban}}
                }
                """)!
            );

            return Results.StatusCode(403, new
            {
                success = false,
                reason = "HWID_BANNED",
                retryAfter = 86400
            });
        }

        // ---------------- SUCCESS ----------------
        await PutJson(
            $"{firebaseDb}/hwid_attempts/{hwid}.json",
            JsonNode.Parse($$"""
            {
                "count": 0,
                "lastFail": {{now}},
                "banUntil": 0
            }
            """)!
        );

        return Results.Ok(new
        {
            success = true,
            name = user["name"]?.GetValue<string>()
        });
    }
    catch (Exception ex)
    {
        return Results.StatusCode(500,
            new { success = false, error = ex.Message });
    }
});

app.Run();


// ================= HELPERS =================

static string ComputeHmac(string raw)
{
    using var hmac =
        new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));
    byte[] hash =
        hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash).ToLower();
}

static async Task<JsonNode> GetJson(string url)
{
    using HttpClient http = new();
    var res = await http.GetStringAsync(url);
    return JsonNode.Parse(res)!;
}

static async Task PutJson(string url, JsonNode body)
{
    using HttpClient http = new();
    var content =
        new StringContent(body.ToJsonString(),
        Encoding.UTF8, "application/json");
    await http.PutAsync(url, content);
}

static async Task RegisterFail(string hwid)
{
    // optional – already handled inline
}
