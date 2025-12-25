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
      sig: string }

// ================= APP =================

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

// ================= ENV =================

let firebaseDbUrl =
    match Environment.GetEnvironmentVariable("FIREBASE_DB_URL") with
    | null | "" -> failwith "FIREBASE_DB_URL not set"
    | v -> v

// ================= SECURITY =================

let SECRET_KEY = "HMX_BY_MR_ARPIT_120"

let computeHmac (input: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET_KEY))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    |> Convert.ToHexString
    |> fun x -> x.ToLowerInvariant()

// ================= HTTP =================

let http = new HttpClient()

let getJsonAsync (url: string) =
    async {
        let! res = http.GetAsync(url) |> Async.AwaitTask
        let! txt = res.Content.ReadAsStringAsync() |> Async.AwaitTask
        return JsonDocument.Parse(txt).RootElement
    }

// ================= HEALTH =================

app.MapGet("/", fun () ->
    Results.Text("AuthServer running")
) |> ignore

// ================= API =================

app.MapPost("/hmx/oauth", fun (ctx: HttpContext) ->
    async {
        try
            let! req =
                JsonSerializer.DeserializeAsync<OAuthRequest>(
                    ctx.Request.Body,
                    JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                )
                |> Async.AwaitTask

            if isNull req then
                return Results.BadRequest("Invalid JSON")

            let raw = $"{req.id}{req.hwid}{req.nonce}"
            let expectedSig = computeHmac raw

            if expectedSig <> req.sig.ToLowerInvariant() then
                return Results.Json(
                    {| success = false; error = "Invalid signature" |},
                    statusCode = 401
                )
            else
                let! appJson = getJsonAsync $"{firebaseDbUrl}/app.json"
                let! userJson = getJsonAsync $"{firebaseDbUrl}/users/{req.id}.json"

                if userJson.ValueKind = JsonValueKind.Null then
                    return Results.Json(
                        {| success = false; error = "User not found" |},
                        statusCode = 404
                    )
                else
                    return Results.Ok(
                        {| success = true
                           app = appJson
                           user = userJson |}
                    )
        with ex ->
            return Results.Json(
                {| success = false; error = ex.Message |},
                statusCode = 500
            )
    }
    |> Async.StartAsTask
) |> ignore

// ================= RUN =================

app.Run()
