using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Text.Json;

// ================= CONFIG =================
const string SERVER_VERSION = "1.0.0";
const int MAX_ATTEMPTS = 3;
const int BAN_SECONDS = 86400; // 1 day

// ================= APP =================
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ================= IN-MEMORY STORE =================
var hwidAttempts = new Dictionary<string, AttemptInfo>();

app.MapGet("/", () => "AuthServer running");

// ================= AUTH ENDPOINT =================
app.MapPost("/auth", async (HttpContext ctx) =>
{
    AuthRequest? req;

    try
    {
        req = await ctx.Request.ReadFromJsonAsync<AuthRequest>();
    }
    catch
    {
        return Results.Json(new { error = "Invalid JSON" }, statusCode: 400);
    }

    if (req == null || string.IsNullOrWhiteSpace(req.Hwid))
        return Results.Json(new { error = "Invalid request" }, statusCode: 400);

    // ---------- VERSION CHECK ----------
    if (req.Version != SERVER_VERSION)
    {
        return Results.Json(new
        {
            success = false,
            reason = "VERSION_MISMATCH",
            requiredVersion = SERVER_VERSION
        }, statusCode: 426);
    }

    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    if (!hwidAttempts.TryGetValue(req.Hwid, out var info))
    {
        info = new AttemptInfo();
        hwidAttempts[req.Hwid] = info;
    }

    // ---------- BAN CHECK ----------
    if (info.BanUntil > now)
    {
        return Results.Json(new
        {
            success = false,
            reason = "HWID_BANNED",
            retryAfter = info.BanUntil - now
        }, statusCode: 403);
    }

    // ---------- AUTH LOGIC ----------
    bool authSuccess = req.Id == "admin"; // replace later

    if (!authSuccess)
    {
        info.Count++;

        if (info.Count >= MAX_ATTEMPTS)
        {
            info.BanUntil = now + BAN_SECONDS;
            info.Count = 0;

            return Results.Json(new
            {
                success = false,
                reason = "HWID_BANNED",
                retryAfter = BAN_SECONDS
            }, statusCode: 403);
        }

        return Results.Json(new
        {
            success = false,
            reason = "INVALID_CREDENTIALS",
            attemptsLeft = MAX_ATTEMPTS - info.Count
        }, statusCode: 401);
    }

    // ---------- SUCCESS ----------
    info.Count = 0;
    info.BanUntil = 0;

    return Results.Ok(new
    {
        success = true,
        message = "Authenticated"
    });
});

app.Run();


// ================= MODELS (MUST BE AT END) =================

record AuthRequest(string Id, string Hwid, string Version);

class AttemptInfo
{
    public int Count { get; set; }
    public long BanUntil { get; set; }
}
