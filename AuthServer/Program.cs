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
        Console.WriteLine("---- SIGNATURE DEBUG START ----");
        Console.WriteLine($"ID      : {id}");
        Console.WriteLine($"HWID    : {hwid}");
        Console.WriteLine($"VERSION : {version}");
        Console.WriteLine($"NONCE   : {nonce}");
        Console.WriteLine($"RAW     : {raw}");
        Console.WriteLine($"SIG_IN  : {sig}");
        Console.WriteLine($"SIG_EXP : {expectedSig}");
        Console.WriteLine("---- SIGNATURE DEBUG END ----");



        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(sig),
                Convert.FromHexString(expectedSig)))

        {
            return Results.Json(new
            {
                success = false,
                reason = "INVALID_SIGNATURE"
            },statusCode: 401);
        }

        // ---------- APP ----------
        JsonNode? appCfg = await GetJson($"{firebaseDb}/app.json");
        if (appCfg == null)
            return Results.Json("AuthServer running", statusCode: 200);

        string serverVersion = appCfg?["version"]?.GetValue<string>() ?? "";


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
            return Results.Json(new
            {
                success = false,
                reason = "INVALID_USER"
            },statusCode: 401);
        }

        // ---------- HWID POLICY (SERVER ONLY) ----------
        if (policy == null)
        {
            return Results.Json(new
            {
                success = false,
                reason = "POLICY_MISSING"
            }, statusCode: 500);
        }
        
bool hwidLocked = policy["hwid_locked"]?.GetValue<bool>() ?? false;
var hwidsNode = policy["hwids"] as JsonObject;

// 🔒 LOCKED → strict check
if (hwidLocked)
{
    if (hwidsNode == null || hwidsNode.Count == 0)
    {
        return Results.Json(new
        {
            success = false,
            reason = "HWIDS_MISSING"
        }, statusCode: 500);
    }

    bool isAllowed = hwidsNode.Any(x => x.Value!.GetValue<string>() == hwid);
    if (!isAllowed)
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
    // 🟢 NOT LOCKED → bind if slot available
    if (hwidsNode == null)
        hwidsNode = new JsonObject();

    bool alreadyBound = hwidsNode.Any(x => x.Value!.GetValue<string>() == hwid);

    if (!alreadyBound)
    {
        var free = hwidsNode.FirstOrDefault(
            x => string.IsNullOrEmpty(x.Value!.GetValue<string>())
        );

        if (free.Key != null)
        {
            hwidsNode[free.Key] = hwid;
            await PutJson($"{firebaseDb}/users/{id}/policy/hwids.json", hwidsNode);
        }
    }
}


        // ---------- FEATURES ----------
 // ---------- HWID POLICY (SERVER ONLY) ----------
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

// 🔒 Only enforce HWID rules when locked
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

    bool hwidExists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);
    if (!hwidExists)
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
    // 🟢 Not locked → auto-bind HWID if slots exist
    if (hwids == null)
        hwids = new JsonObject();

    bool hwidExists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);

    if (!hwidExists)
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
        },statusCode: 500);
    }
});

app.Run();


// ================= HELPERS =================

static string ComputeHmac(string raw)
{
    using var hmac =
        new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));
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



