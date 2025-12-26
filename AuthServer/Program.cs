using System.Security.Cryptography;
using System.Text;
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
        using var reader = new StreamReader(ctx.Request.Body);
        var jsonText = await reader.ReadToEndAsync();
        var body = JsonNode.Parse(jsonText);

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

        // ---------------- APP CONFIG ----------------
        JsonNode appCfg =
            await GetJson($"{firebaseDb}/app.json");

        string serverVersion =
            appCfg["version"]!.GetValue<string>();

        if (version != serverVersion)
        {
            return Results.StatusCode(426, new
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

        // ---------------- HWID POLICY (INTERNAL ONLY) ----------------
        var policy = user["policy"]!;
        int maxDevices = policy["max_devices"]!.GetValue<int>();
        var hwids = policy["hwids"]!.AsObject();

        bool hwidExists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);

        if (!hwidExists)
        {
            var emptySlot = hwids.FirstOrDefault(
                x => string.IsNullOrEmpty(x.Value!.GetValue<string>())
            );

            if (emptySlot.Key == null)
            {
                // lock internally
                policy["hwid_locked"] = true;
                await PutJson($"{firebaseDb}/users/{id}/policy.json", policy);

                return Results.Forbid();
            }

            // assign hwid
            hwids[emptySlot.Key] = hwid;
            await PutJson($"{firebaseDb}/users/{id}/policy/hwids.json", hwids);
        }

        // ---------------- RESET FAIL COUNTER ----------------
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await PutJson(
            $"{firebaseDb}/hwid_attempts/{hwid}.json",
            JsonNode.Parse(
                "{ \"count\": 0, \"lastFail\": " + now + ", \"banUntil\": 0 }"
            )!
        );

        // ---------------- FEATURE FILTERING ----------------
        var features = appCfg["features"]!.AsObject();
        var responseFeatures = new JsonObject();

        foreach (var feature in features)
        {
            bool enabled =
                feature.Value!["enabled"]!.GetValue<bool>();

            int minVersion =
                feature.Value!["min_version"]!.GetValue<int>();

            var f = new JsonObject
            {
                ["enabled"] = enabled,
                ["min_version"] = minVersion
            };

            if (enabled)
            {
                foreach (var kv in feature.Value!.AsObject())
                {
                    if (kv.Key.EndsWith("_api_1"))
                        f[kv.Key] = kv.Value;
                }
            }

            responseFeatures[feature.Key] = f;
        }

        // ---------------- SAFE USER RESPONSE ----------------
        var responseUser = new JsonObject
        {
            ["id"] = id,
            ["name"] = user["name"],
            ["dead_checker"] = user["dead_checker"],
            ["live_checker"] = user["live_checker"],
            ["purchased_checker"] = user["purchased_checker"],
            ["not_purchased_checker"] = user["not_purchased_checker"],
            ["hotmail_inbox"] = user["hotmail_inbox"],
            ["xbox_pass"] = user["xbox_pass"]
        };

        return Results.Ok(new
        {
            success = true,
            user = responseUser,
            features = responseFeatures,
            server_time = now
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
    using var hmac =
        new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));
    byte[] hash =
        hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash).ToLower();
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

static async Task RegisterFail(string hwid)
{
    await Task.CompletedTask;
}
