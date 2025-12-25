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
    match Environment.GetEnvironmentVariable("FIREBASE_DB_URL") with
    | null | "" -> failwith "FIREBASE_DB_URL not set"
    | v -> v

// ================= SECURITY =================

// ⚠️ In production, move this to Render ENV as HMAC_SECRET
let SECRET_KEY : string =
    match Environment.GetEnvironmentVariable("HMAC_SECRET") with
    | null | "" -> "HMX_BY_MR_ARPIT_120"
    | v -> v

let computeHmac (input: string) : string =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET_KEY))
    let hash : byte[] = hmac.ComputeHash(Encoding.UTF8.GetBytes(input))
    BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()

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
                let! req =
                    JsonSerializer.DeserializeAsync<OAuthRequest>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                if isNull req then
                    return Results.Json(
                        {| success = false; error = "Invalid body" |},
                        statusCode = 400
                    )
                else
                    // 🔐 MUST match client-side order exactly
                    let raw =
                        req.id + req.hwid + req.version + req.nonce

                    let expectedSig = computeHmac raw

                    if not (expectedSig.Equals(req.signature, StringComparison.OrdinalIgnoreCase)) then
                        return Results.Json(
                            {| success = false; error = "Invalid signature" |},
                            statusCode = 401
                        )
                    else
                        let! appJson = getJson($"{firebaseDbUrl}/app.json")
                        let! userJson = getJson($"{firebaseDbUrl}/users/{req.id}.json")

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
    )
) |> ignore

// ================= RUN =================

app.Run()
