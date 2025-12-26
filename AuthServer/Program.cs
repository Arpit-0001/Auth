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
            return Results.Json("AuthServer running", statusCode: 200);

        string id = body["id"]!.GetValue<string>();
        string hwid = body["hwid"]!.GetValue<string>();
        string version = body["version"]!.GetValue<string>();
        string nonce = body["nonce"]!.GetValue<string>();
        string sig = body["sig"]!.GetValue<string>();

        // ---------- HMAC ----------
        string raw = id + hwid + version + nonce;
        string expectedSig = ComputeHmac(raw);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(sig),
                Convert.FromHexString(expectedSig)))
        {
            return Results.Json(new
            {
                success = false,
                reason = "INVALID_SIGNATURE"
            }, statusCode: 401);
        }

        // ---------- APP ----------
        JsonNode? appCfg = await GetJson($"{firebaseDb}/app.json");
        if (appCfg == null)
            return Results.Json("AuthServer running", statusCode: 200);

        string serverVersion = appCfg["version"]!.GetValue<string>();

        if (Version.Parse(version) != Version.Parse(serverVersion))
        {
            return Results.Json(new
            {
                success = false,
                reason = "UPDATE_REQUIRED",
                requiredVersion = serverVersion
            }, statusCode: 426);
        }

        // ---------- USER ----------
        JsonNode? user = await GetJson($"{firebaseDb}/users/{id}.json");
        if (user == null)
        {
            return Results.Json(new
            {
                success = false,
                reason = "INVALID_USER"
            }, statusCode: 401);
        }

        // ---------- HWID POLICY ----------
        var policy = user["policy"] as JsonObject;
        if (policy == null)
        {
            return Results.Json(new
            {
                success = false,
                reason = "POLICY_MISSING"
            }, statusCode: 500);
        }

        bool hwidLocked = policy["hwid_locked"]?.GetValue<bool>() ?? false;
        var hwids = policy["hwids"] as JsonObject;

        if (hwidLocked)
        {
            if (hwids == null || hwids.Count == 0)
            {
                return Results.Json(new
                {
                    success = false,
                    reason = "HWIDS_MISSING"
                }, statusCode: 500);
            }

            bool allowed = hwids.Any(x => x.Value!.GetValue<string>() == hwid);
            if (!allowed)
            {
                return Results.Json(new
                {
                    success = false,
                    reason = "HWID_NOT_ALLOWED"
                }, statusCode: 403);
            }
        }
        else
        {
            if (hwids == null)
                hwids = new JsonObject();

            bool exists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);
            if (!exists)
            {
                var free = hwids.FirstOrDefault(
                    x => string.IsNullOrEmpty(x.Value!.GetValue<string>())
                );

                if (free.Key != null)
                {
                    hwids[free.Key] = hwid;
                    await PutJson($"{firebaseDb}/users/{id}/policy/hwids.json", hwids);
                }
            }
        }

        // ---------- FEATURES ----------
        var featuresCfg = appCfg["features"]!.AsObject();
        var featuresOut = new JsonObject();

        foreach (var f in featuresCfg)
        {
            featuresOut[f.Key] = new JsonObject
            {
                ["enabled"] = f.Value!["enabled"],
                ["min_version"] = f.Value!["min_version"]
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
                dead_checker = user["dead_checker"],
                live_checker = user["live_checker"],
                purchased_checker = user["purchased_checker"],
                not_purchased_checker = user["not_purchased_checker"],
                hotmail_inbox = user["hotmail_inbox"],
                xbox_pass = user["xbox_pass"]
            },
            features = featuresOut,
            server_time = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new
        {
            success = false,
            error = ex.Message
        }, statusCode: 500);
    }
});

app.Run();

// ================= HELPERS =================

static string ComputeHmac(string raw)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));
    return Convert.ToHexString(
        hmac.ComputeHash(Encoding.UTF8.GetBytes(raw))
    ).ToLower();
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
    await http.PutAsync(
        url,
        new StringContent(
            body.ToJsonString(),
            Encoding.UTF8,
            "application/json"
        )
    );
}
