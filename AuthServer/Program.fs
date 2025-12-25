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
    match Environment.GetEnvironmentVariable("FIREBASE_DB_URL") with
    | null | "" -> failwith "FIREBASE_DB_URL environment variable not set"
    | v -> v.TrimEnd('/')

// ================= SECURITY =================

let SECRET_KEY = "HMX_BY_MR_ARPIT_120"

let computeHmac (input: string) =
    use hmac =
        new HMACSHA256(Encoding.UTF8.GetBytes(SECRET_KEY))
    hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    |> Convert.ToHexString
    |> fun s -> s.ToLowerInvariant()

// ================= HTTP =================

let httpClient = new HttpClient()

let getJson (url: string) =
    task {
        let! res = httpClient.GetAsync(url)
        let! body = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(body).RootElement
    }

// ================= HEALTH =================

app.MapGet(
    "/",
    Func<IResult>(fun () ->
        Results.Text("AuthServer running")
    )
) |> ignore

// ================= API =================

app.MapPost(
    "/hmx/oauth",
    Func<HttpContext, Threading.Tasks.Task<IResult>>(fun ctx ->
        task {
            try
                let! req =
                    JsonSerializer.DeserializeAsync<OAuthRequest>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                // ---- Validate fields (NO null checks) ----
                if String.IsNullOrWhiteSpace(req.id)
                   || String.IsNullOrWhiteSpace(req.hwid)
                   || String.IsNullOrWhiteSpace(req.version)
                   || String.IsNullOrWhiteSpace(req.nonce)
                   || String.IsNullOrWhiteSpace(req.signature) then

                    return Results.Json(
                        {| success = false; error = "Missing required fields" |},
                        statusCode = 400
                    )

                // ---- Verify HMAC ----
                let raw =
                    req.id + req.hwid + req.version + req.nonce

                let expectedSig = computeHmac raw

                if not (expectedSig.Equals(req.signature, StringComparison.OrdinalIgnoreCase)) then
                    return Results.Json(
                        {| success = false; error = "Invalid signature" |},
                        statusCode = 401
                    )

                // ---- Fetch Firebase data ----
                let! appJson =
                    getJson($"{firebaseDbUrl}/app.json")

                let! userJson =
                    getJson($"{firebaseDbUrl}/users/{req.id}.json")

                if userJson.ValueKind = JsonValueKind.Null then
                    return Results.Json(
                        {| success = false; error = "User not found" |},
                        statusCode = 404
                    )

                // ---- Success ----
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
