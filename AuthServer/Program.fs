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

// ================= APP =================

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

// ================= ENV =================

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")

if String.IsNullOrWhiteSpace(firebaseDbUrl) then
    failwith "FIREBASE_DB_URL not set"

// ================= SECURITY =================

let SECRET = "HMX_SUPER_SECRET_2025"

let computeHmac (input: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    |> Convert.ToHexString

// ================= HTTP =================

let http = new HttpClient()

let getJson (url: string) =
    task {
        let! res = http.GetAsync(url)
        let! txt = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(txt).RootElement
    }

// ================= HEALTH =================

app.MapGet("/", Func<IResult>(fun () ->
    Results.Text("AuthServer running")
)) |> ignore

// ================= API =================

app.MapPost(
    "/hmx/oauth",
    Func<HttpContext, Threading.Tasks.Task<IResult>>(fun ctx ->
        task {
            try
                let! body =
                    JsonSerializer.DeserializeAsync<OAuthRequest>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                // ---- HMAC VERIFY ----
                let raw = body.id + body.hwid + body.nonce
                let expected = computeHmac raw

                if not (expected.Equals(body.signature, StringComparison.OrdinalIgnoreCase)) then
                    return Results.Json(
                        {| success = false; error = "Invalid signature" |},
                        statusCode = 401
                    )

                // ---- FIREBASE ----
                let! appJson = getJson($"{firebaseDbUrl}/app.json")
                let! userJson = getJson($"{firebaseDbUrl}/users/{body.id}.json")

                if userJson.ValueKind = JsonValueKind.Null then
                    return Results.Json(
                        {| success = false; error = "User not found" |},
                        statusCode = 404
                    )

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
    )
) |> ignore

// ================= RUN =================

app.Run()
