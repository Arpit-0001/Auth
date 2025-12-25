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
    task {
        let! res = http.GetAsync(url)
        let! txt = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(txt).RootElement
    }

let putJson (url: string) (body: obj) =
    task {
        let json = JsonSerializer.Serialize(body)
        let content = new StringContent(json, Encoding.UTF8, "application/json")
        let! _ = http.PutAsync(url, content)
        return ()
    }

// ================= HEALTH =================

app.MapGet("/", Func<IResult>(fun () ->
    Results.Text("AuthServer running")
)) |> ignore

// ================= API =================

app.MapPost(
    "/hmx/oauth",
    Func<HttpContext, Task<IResult>>(fun ctx ->
        task {
            try
                // ===== READ BODY =====
                let! req =
                    ctx.Request.ReadFromJsonAsync<OAuthRequest>()

                // ===== HMAC CHECK =====
                let raw = req.id + req.hwid + req.version + req.nonce
                let expectedSig = computeHmac raw

                if not (expectedSig.Equals(req.sig_, StringComparison.OrdinalIgnoreCase)) then
                    return Results.Json(
                        {| success = false; error = "Invalid signature" |},
                        statusCode = 401
                    )

                let now = DateTimeOffset.UtcNow.ToUnixTimeSeconds()

                // ===== HWID ATTEMPTS =====
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
                    return Results.Json(
                        {| success = false
                           reason = "HWID_BANNED"
                           retryAfter = banUntil - now |},
                        statusCode = 403
                    )

                // ===== VERSION CHECK =====
                let! appJson = getJson $"{firebaseDbUrl}/app.json"
                let serverVersion = appJson.GetProperty("version").GetString()

                if req.version <> serverVersion then
                    return Results.Json(
                        {| success = false
                           reason = "VERSION_MISMATCH"
                           requiredVersion = serverVersion |},
                        statusCode = 426
                    )

                // ===== USER CHECK =====
                let! userJson = getJson $"{firebaseDbUrl}/users/{req.id}.json"

                if userJson.ValueKind = JsonValueKind.Null then
                    attempts <- attempts + 1
                    let banTime = if attempts >= 3 then now + 86400L else 0L

                    do!
                        putJson hwidPath
                            {| count = attempts
                               lastFail = now
                               banUntil = banTime |}

                    return Results.Json(
                        {| success = false
                           error = "Invalid ID"
                           attemptsLeft = max 0 (3 - attempts) |},
                        statusCode = 401
                    )

                // ===== SUCCESS =====
                do! http.DeleteAsync(hwidPath)

                return Results.Ok(
                    {| success = true
                       user = userJson |}
                )

            with ex ->
                return Results.Json(
                    {| success = false; error = ex.Message |},
                    statusCode = 500
                )
        }
    )
) |> ignore

// ================= RUN =================

app.Run()
