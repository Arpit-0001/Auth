using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// ================= CONFIG =================
string firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")?.TrimEnd('/') ?? "";

string secretKey =
    Environment.GetEnvironmentVariable("AUTH_SECRET") ?? "CHANGE_THIS_SECRET";

// ================= APP =================
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

HttpClient http = new();

// ================= HELPERS =================
static async Task<JsonNode?> GetJson(HttpClient http, string url)
{
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode) return null;

    var txt = await res.Content.ReadAsStringAsync();
    if (string.IsNullOrWhiteSpace(txt) || txt == "null") return null;

    return JsonNode.Parse(txt);
}

static async Task PutJson(HttpClient http, string url, JsonNode body)
{
    var json = body.ToJsonString();
    var content = new StringContent(json, Encoding.UTF8, "application/json");
    await http.PutAsync(url, content);
}

static string ComputeHmac(string raw, string secret)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash).ToLower();
}

// ================= ROOT =================
app.MapGet("/", () => Results.Ok("AuthServer running"));

// ================= POST /hmx/oauth =================
app.MapPost("/hmx/oauth", async (HttpContext ctx) =>
{
    string rawBody;
    using (var reader = new StreamReader(ctx.Request.Body))
        rawBody = await reader.ReadToEndAsync();

    JsonNode? body;
    try
    {
        body = JsonNode.Parse(rawBody);
    }
    catch
    {
        return Results.Json(new { success = false, error = "INVALID_JSON" }, statusCode: 400);
    }

    // ================= AUTH HEADER =================
    if (!ctx.Request.Headers.TryGetValue("X-Signature", out var sigHeader))
    {
        return Results.Json(new { success = false, reason = "NO_SIGNATURE" }, statusCode: 401);
    }

    string expected = ComputeHmac(rawBody, secretKey);
    string provided = sigHeader.ToString().ToLower();

    if (expected != provided)
    {
        return Results.Json(new { success = false, reason = "INVALID_SIGNATURE" }, statusCode: 401);
    }

    // ================= BASIC FIELDS =================
    if (body?["id"] == null || body["version"] == null)
    {
        return Results.Json(new { success = false, error = "MISSING_FIELDS" }, statusCode: 400);
    }

    string id = body["id"]!.GetValue<string>();
    string hwid = body["hwid"]?.GetValue<string>() ?? "unknown";
    double clientVersion = body["version"]!.GetValue<double>();

    // ================= APP CONFIG =================
    var appCfg = await GetJson(http, $"{firebaseDbUrl}/app.json");
    if (appCfg == null || appCfg["version"] == null)
    {
        return Results.Json(new { success = false, error = "SERVER_CONFIG_ERROR" }, statusCode: 500);
    }

    double serverVersion = appCfg["version"]!.GetValue<double>();

    if (clientVersion != serverVersion)
    {
        return Results.Json(new
        {
            success = false,
            reason = "VERSION_MISMATCH",
            requiredVersion = serverVersion
        }, statusCode: 426);
    }

    // ================= USER =================
    var user = await GetJson(http, $"{firebaseDbUrl}/users/{id}.json");
    if (user == null)
    {
        return Results.Json(new { success = false, reason = "INVALID_USER" }, statusCode: 401);
    }

    // ================= HWID ATTEMPTS =================
    var attempt = await GetJson(http, $"{firebaseDbUrl}/hwid_attempts/{hwid}.json");

    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    int count = attempt?["count"]?.GetValue<int>() ?? 0;
    long banUntil = attempt?["banUntil"]?.GetValue<long>() ?? 0;

    if (banUntil > now)
    {
        return Results.Json(new
        {
            success = false,
            reason = "HWID_BANNED",
            retryAfter = banUntil - now
        }, statusCode: 403);
    }

    if (count >= 3)
    {
        long ban = now + 86400;

        await PutJson(http,
            $"{firebaseDbUrl}/hwid_attempts/{hwid}.json",
            JsonNode.Parse($$"""
            {
              "count": {{count}},
              "lastFail": {{now}},
              "banUntil": {{ban}}
            }
            """)!
        );

        return Results.Json(new
        {
            success = false,
            reason = "HWID_BANNED",
            retryAfter = 86400
        }, statusCode: 403);
    }

    // ================= SUCCESS =================
    await PutJson(http,
        $"{firebaseDbUrl}/hwid_attempts/{hwid}.json",
        JsonNode.Parse($$"""
        {
          "count": {{count + 1}},
          "lastFail": {{now}},
          "banUntil": 0
        }
        """)!
    );

    return Results.Ok(new
    {
        success = true,
        name = user["name"]?.GetValue<string>(),
        features = user
    });
});

app.Run();
