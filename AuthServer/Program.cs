using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var http = new HttpClient();

string firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")?.TrimEnd('/') ?? "";

async Task<JsonNode?> GetJson(string url)
{
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode) return null;
    var txt = await res.Content.ReadAsStringAsync();
    return JsonNode.Parse(txt);
}

async Task PutJson(string url, JsonNode body)
{
    var json = body.ToJsonString();
    var content = new StringContent(json, Encoding.UTF8, "application/json");
    await http.PutAsync(url, content);
}

app.MapGet("/", () => "AuthServer running");

app.MapPost("/hmx/oauth", async (HttpContext ctx) =>
{
    try
    {
        using var reader = new StreamReader(ctx.Request.Body);
        var raw = await reader.ReadToEndAsync();
        var body = JsonNode.Parse(raw);

        if (body?["id"] == null)
            return Results.BadRequest(new { success = false, error = "id missing" });

        string id = body["id"]!.GetValue<string>();
        string hwid = body["hwid"]!.GetValue<string>();
        double clientVersion = body["version"]!.GetValue<double>();

        // ---- version check ----
        var appCfg = await GetJson($"{firebaseDbUrl}/app.json");
        double serverVersion = appCfg!["version"]!.GetValue<double>();

        if (clientVersion != serverVersion)
        {
            return Results.StatusCode(426, new
            {
                success = false,
                reason = "VERSION_MISMATCH",
                requiredVersion = serverVersion
            });
        }

        // ---- user ----
        var user = await GetJson($"{firebaseDbUrl}/users/{id}.json");
        if (user == null)
            return Results.Unauthorized();

        // ---- HWID attempts ----
        var attempt = await GetJson($"{firebaseDbUrl}/hwid_attempts/{hwid}.json");
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

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
                $"{firebaseDbUrl}/hwid_attempts/{hwid}.json",
                JsonNode.Parse($@"{{ ""count"": {count}, ""lastFail"": {now}, ""banUntil"": {ban} }}")!
            );

            return Results.StatusCode(403, new
            {
                success = false,
                reason = "HWID_BANNED",
                retryAfter = 86400
            });
        }

        // success
        await PutJson(
            $"{firebaseDbUrl}/hwid_attempts/{hwid}.json",
            JsonNode.Parse($@"{{ ""count"": {count + 1}, ""lastFail"": {now}, ""banUntil"": 0 }}")!
        );

        return Results.Ok(new { success = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
});

app.Run();
