open System
open System.Net.Http
open System.Text
open System.Text.Json
open System.Text.Json.Serialization
open System.Security.Cryptography
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting

// ================= MODELS =================

type OAuthRequest =
    { id: string
      hwid: string
      version: string
      nonce: string
      [<JsonPropertyName("sig")>]
      sig_: string }

// ================= APP =================

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

// ================= ENV =================

let firebaseDbUrl =
    match Environment.GetEnvironmentVariable("FIREBASE_DB_URL") with
    | null | "" -> failwith "FIREBASE_DB_URL not set"
    | v -> v.TrimEnd('/')

// ================= SECURITY =================

let SECRET_KEY = "HMX_BY_MR_ARPIT_120"

let computeHmac (input: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET_KEY))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    |> Array.map (fun b -> b.ToString("x2"))
    |> String.concat ""

// ================= HTTP =================

let http = new HttpClient()

let getJson (url: string) =
    async {
        let! res = http.GetAsync(url) |> Async.AwaitTask
        let! txt = res.Content.ReadAsStringAsync() |> Async.AwaitTask
        return JsonDocument.Parse(txt).RootElement
    }

let putJson (url: string) (body: obj) =
    async {
        let json = JsonSerializer.Serialize(body)
        let content = new StringContent(json, Encoding.UTF8, "application/json")
        let! _ = http.PutAsync(url, content) |> Async.AwaitTask
        return ()
    }

// ================= HEALTH =================

app.MapGet("/", Func<IResult>(fun () ->
    Results.Text("AuthServer running")
)) |> ignore

// ================= API =================

open Microsoft.AspNetCore.Http.Json

app.MapPost("/hmx/oauth",
    Func<HttpContext, Threading.Tasks.Task<IResult>>(fun ctx ->
        task {
            try
                // ✅ FIX 1: ReadFromJsonAsync returns ValueTask
                let! req = ctx.Request.ReadFromJsonAsync<OAuthRequest>()

                if isNull req then
                    return Results.BadRequest(
                        {| success = false; error = "Invalid request body" |}
                    )

                // ===== HMAC =====
                let raw = req.id + req.hwid + req.version + req.nonce
                let expectedSig = computeHmac raw

                if not (expectedSig.Equals(req.sig_, StringComparison.OrdinalIgnoreCase)) then
                    return Results.Unauthorized()

                let now = DateTimeOffset.UtcNow.ToUnixTimeSeconds()

                // ===== HWID CHECK =====
                let hwidPath = $"{firebaseDbUrl}/hwid_attempts/{req.hwid}.json"
                let! hwidJson = getJson hwidPath

                let mutable attempts = 0
                let mutable banUntil = 0L

                if hwidJson.ValueKind <> JsonValueKind.Null then
                    let mutable c = Unchecked.defaultof<JsonElement>
                    let mutable b = Unchecked.defaultof<JsonElement>

                    if hwidJson.TryGetProperty("count", &c) then
                        attempts <- c.GetInt32()

                    if hwidJson.TryGetProperty("banUntil", &b) then
                        banUntil <- b.GetInt64()

                if banUntil > now then
                    return Results.StatusCode(
                        StatusCodes.Status403Forbidden,
                        {| success = false; reason = "HWID_BANNED"; retryAfter = banUntil - now |}
                    )

                // ===== VERSION CHECK =====
                let! appJson = getJson $"{firebaseDbUrl}/app.json"
                let serverVersion = appJson.GetProperty("version").GetString()

                if req.version <> serverVersion then
                    return Results.StatusCode(
                        StatusCodes.Status426UpgradeRequired,
                        {| success = false; reason = "VERSION_MISMATCH"; requiredVersion = serverVersion |}
                    )

                // ===== USER CHECK =====
                let! userJson = getJson $"{firebaseDbUrl}/users/{req.id}.json"

                if userJson.ValueKind = JsonValueKind.Null then
                    attempts <- attempts + 1
                    let ban = if attempts >= 3 then now + 86400L else 0L

                    do!
                        putJson hwidPath
                            {| count = attempts
                               lastFail = now
                               banUntil = ban |}

                    return Results.Unauthorized(
                        {| success = false
                           error = "Invalid ID"
                           attemptsLeft = max 0 (3 - attempts) |}
                    )

                // ===== SUCCESS =====
                do! http.DeleteAsync(hwidPath)

                return Results.Ok(
                    {| success = true
                       user = userJson |}
                )
            with ex ->
                return Results.Problem(ex.Message)
        }
    )
) |> ignore


// ================= RUN =================

app.Run()
