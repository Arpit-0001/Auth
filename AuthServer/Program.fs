open System
open System.Net.Http
open System.Text
open System.Text.Json
open System.Text.Json.Serialization
open System.Security.Cryptography
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
      sigValue: string }

// ================= APP =================

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

// ================= ENV =================

let firebaseDbUrl =
    match Environment.GetEnvironmentVariable("FIREBASE_DB_URL") with
    | null | "" -> failwith "FIREBASE_DB_URL not set"
    | v -> v

// ================= SECURITY =================

let SECRET_KEY =
    match Environment.GetEnvironmentVariable("SECRET_KEY") with
    | null | "" -> "HMX_BY_MR_ARPIT_120"   // fallback
    | v -> v

let computeHmac (input: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET_KEY))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    |> Convert.ToHexString
    |> fun s -> s.ToLowerInvariant()

// ================= HTTP =================

let http = new HttpClient()

let getJson (url: string) =
    task {
        let! res = http.GetAsync(url)
        let! txt = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(txt).RootElement
    }

// ================= HEALTH =================

app.MapGet("/", fun () ->
    Results.Text("AuthServer running")
) |> ignore

// ================= API =================

app.MapPost(
    "/hmx/oauth",
    RequestDelegate(fun ctx ->
        task {
            try
                let! req =
                    JsonSerializer.DeserializeAsync<OAuthRequest>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                if isNull req then
                    return! Results.BadRequest("Invalid JSON").ExecuteAsync(ctx)

                let raw = req.id + req.hwid + req.version + req.nonce
                let expectedSig = computeHmac raw

                if not (String.Equals(expectedSig, req.sigValue, StringComparison.OrdinalIgnoreCase)) then
                    let res =
                        Results.Json(
                            {| success = false; error = "Invalid signature" |},
                            statusCode = 401
                        )
                    return! res.ExecuteAsync(ctx)

                let! appJson = getJson $"{firebaseDbUrl}/app.json"
                let! userJson = getJson $"{firebaseDbUrl}/users/{req.id}.json"

                if userJson.ValueKind = JsonValueKind.Null then
                    let res =
                        Results.Json(
                            {| success = false; error = "User not found" |},
                            statusCode = 404
                        )
                    return! res.ExecuteAsync(ctx)

                let res =
                    Results.Ok(
                        {| success = true
                           app = appJson
                           user = userJson |}
                    )

                return! res.ExecuteAsync(ctx)

            with ex ->
                let res =
                    Results.Json(
                        {| success = false; error = ex.Message |},
                        statusCode = 500
                    )
                return! res.ExecuteAsync(ctx)
        }
    )
) |> ignore

// ================= RUN =================

app.Run()
