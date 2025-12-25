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
      signature: string }

// ================= APP SETUP =================

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

// ================= ENV =================

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")

if String.IsNullOrWhiteSpace(firebaseDbUrl) then
    failwith "FIREBASE_DB_URL environment variable not set"

// ================= SECURITY =================

let SECRET = "HMX_SUPER_SECRET_2025"

let computeHmac (data: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(data))
    |> Convert.ToHexString

// ================= HTTP =================

let httpClient = new HttpClient()

let getJson (url: string) =
    task {
        let! res = httpClient.GetAsync(url)
        let! body = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(body).RootElement
    }

// ================= HEALTH =================

app.MapGet("/", fun () ->
    Results.Text("AuthServer running")
) |> ignore

// ================= API =================

app.MapPost("/hmx/oauth", fun (ctx: HttpContext) ->
    task {
        try
            let! req =
                JsonSerializer.DeserializeAsync<OAuthRequest>(
                    ctx.Request.Body,
                    JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                )

            if isNull req then
                return Results.BadRequest(
                    {| success = false; error = "Invalid request body" |}
                )
            else
                // ---- HMAC VERIFY ----
                let raw = req.id + req.hwid + req.nonce
                let expected = computeHmac raw

                if not (expected.Equals(req.signature, StringComparison.OrdinalIgnoreCase)) then
                    return Results.Unauthorized(
                        {| success = false; error = "Invalid signature" |}
                    )
                else
                    // ---- FIREBASE ----
                    let! appJson =
                        getJson($"{firebaseDbUrl}/app.json")

                    let! userJson =
                        getJson($"{firebaseDbUrl}/users/{req.id}.json")

                    if userJson.ValueKind = JsonValueKind.Null then
                        return Results.NotFound(
                            {| success = false; error = "User not found" |}
                        )
                    else
                        return Results.Ok(
                            {| success = true
                               app = appJson
                               user = userJson |}
                        )
        with ex ->
            return Results.Problem(ex.Message)
    }
) |> ignore

// ================= RUN =================

app.Run()
