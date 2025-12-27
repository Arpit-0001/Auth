using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "HMX_BY_MR_ARPIT_120";

string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
        .TrimEnd('/');

app.MapGet("/", () => "AuthServer running");

app.MapPost("/hmx/oauth", async (HttpContext ctx) =>
{
    try
    {
        using var reader = new StreamReader(ctx.Request.Body);
        var body = JsonNode.Parse(await reader.ReadToEndAsync());
        if (body == null)
            return Results.Json("AuthServer running");

        string id = body["id"]!.GetValue<string>();
        string hwid = Convert.ToHexString(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(body["hwid"]!.GetValue<string>())
            )
        );
        string version = body["version"]!.GetValue<string>();
        string nonce = body["nonce"]!.GetValue<string>();
        string sig = body["sig"]!.GetValue<string>();

        // ---------- HWID BAN CHECK ----------
        var hwidAttempt = await GetJson($"{firebaseDb}/hwid_attempts/{hwid}.json");
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        if (hwidAttempt != null)
        {
            bool banned = hwidAttempt["banned"]?.GetValue<bool>() ?? false;
            long banUntil = hwidAttempt["banUntil"]?.GetValue<long>() ?? 0;
        
            if (banned && now < banUntil)
            {
                return Results.Json(new
                {
                    success = false,
                    reason = "HWID_BANNED",
                    remaining = banUntil - now
                }, statusCode: 403);
            }
        }
        
        // ---------- HMAC ----------
        string raw = id + hwid + version + nonce;
        string expectedSig = ComputeHmac(raw);


        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(sig),
                Convert.FromHexString(expectedSig)))
        {
            var remaining = await RegisterFailedAttempt(hwid);
            return Results.Json(new
            {
                success = false,
                reason = "INVALID_SIGNATURE",
                remaining_attempts = remaining
            }, statusCode: 401);
        }



        // ---------- HWID BAN CHECK ----------

        // ---------- APP ----------
        JsonNode? appCfg = await GetJson($"{firebaseDb}/app.json");
        if (appCfg == null)
            return Results.Json("AuthServer running");

        string serverVersion = appCfg["version"]!.GetValue<string>();
        if (Version.Parse(version) != Version.Parse(serverVersion))
        {
            return Results.Json(new
            {
                success = false,
                reason = "UPDATE_REQUIRED",
                requiredVersion = serverVersion
            },statusCode: 426);
        }

        // ---------- USER ----------
        JsonNode? user = await GetJson($"{firebaseDb}/users/{id}.json");
        if (user == null)
        {
            await RegisterFailedAttempt(hwid);
            return Results.Json(new { success = false, reason = "INVALID_USER" },statusCode: 401);
        }

        // ---------- POLICY ----------
        var policy = user["policy"] as JsonObject;
        if (policy == null)
            return Results.Json(new { success = false, reason = "POLICY_MISSING" },statusCode: 500);

        bool hwidLocked = policy["hwid_locked"]?.GetValue<bool>() ?? false;
        var hwids = policy["hwids"] as JsonObject ?? new JsonObject();

        if (hwidLocked)
        {
            if (!hwids.Any(x => x.Value!.GetValue<string>() == hwid))
            {
                await RegisterFailedAttempt(hwid);
                return Results.Json(new { success = false, reason = "HWID_NOT_ALLOWED" },statusCode: 403);
            }
        }
        else
        {
            bool exists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);
            if (!exists)
            {
                var free = hwids.FirstOrDefault(x => string.IsNullOrEmpty(x.Value!.GetValue<string>()));
                if (free.Key != null)
                {
                    hwids[free.Key] = hwid;
                    await PutJson($"{firebaseDb}/users/{id}/policy/hwids.json", hwids);
                }
            }
        }

        // ---------- FEATURES ----------
        var appFeatures = appCfg["features"] as JsonObject ?? new JsonObject();
        var featuresOut = new JsonObject();

        foreach (var f in appFeatures)
        {
            bool enabled = f.Value!["enabled"]!.GetValue<bool>();
            string minVersion = f.Value!["min_version"]!.GetValue<string>();

            featuresOut[f.Key] = enabled
                ? new JsonObject
                {
                    ["enabled"] = true,
                    ["min_version"] = minVersion
                }
                : new JsonObject
                {
                    ["enabled"] = false
                };
        }



        
        // ---------- SUCCESS ----------
        return Results.Json(new
        {

            success = true,
            user = new
            {
                id,
                name = user["name"],
                dead_checker = user["dead_checker"]!.GetValue<string>(),
                live_checker = user["live_checker"]!.GetValue<string>(),
                purchased_checker = user["purchased_checker"]!.GetValue<string>(),
                not_purchased_checker = user["not_purchased_checker"]!.GetValue<string>(),
                hotmail_inbox = user["hotmail_inbox"],
                xbox_pass = user["xbox_pass"]
            },
            features = featuresOut,
            server_time = now
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message },statusCode: 500);
    }
});

app.Run();


// ================= HELPERS =================

static string ComputeHmac(string raw)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));
    return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLower();
}

static async Task<JsonNode?> GetJson(string url)
{
    using HttpClient http = new();
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode)
        return null;
    return JsonNode.Parse(await res.Content.ReadAsStringAsync());
}

static async Task PutJson(string url, JsonNode body)
{
    using HttpClient http = new();
    await http.PutAsync(url,
        new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"));
}

static async Task<int> RegisterFailedAttempt(string hwid)
{
    string baseUrl = Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!.TrimEnd('/');
    var node = await GetJson($"{baseUrl}/hwid_attempts/{hwid}.json");
    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    int count = node?["count"] != null
        ? node["count"]!.GetValue<int>()
        : 3;

    count--;

    if (count <= 0)
    {
        await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
        {
            ["count"] = 0,
            ["banned"] = true,
            ["banUntil"] = now + 86400
        });
        return 0;
    }

    await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
    {
        ["count"] = count,
        ["banned"] = false,
        ["banUntil"] = 0
    });

    return count;
}
