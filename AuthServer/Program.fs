open System
open System.Net.Http
open System.Text
open System.Text.Json
open System.Security.Cryptography
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection

// ================= MODELS =================

type OAuthRequest =
    { id: string
      hwid: string
      version: string
      nonce: string
      sig: string }

// ================= APP SETUP =================

let builder = WebApplication.CreateBuilder()
builder.Services.AddRouting() |> ignore

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
        let! response = httpClient.GetAsync(url)
        let! body = response.Content.ReadAsStringAsync()
        return JsonDocument.Parse(body).RootElement
    }

// ================= ROOT (Health Check) =================

app.MapGet("/", Func<string>(fun () ->
    "AuthServer running"
)) |> ignore

// ================= API =================

app.MapPost("/hmx/oauth",
    Func<HttpContext, Threading.Tasks.Task>(fun ctx ->
        task {
            try
                let! req =
                    JsonSerializer.DeserializeAsync<OAuthRequest>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                if isNull req then
                    ctx.Response.StatusCode <- 400
                    do! ctx.Response.WriteAsJsonAsync(
                        {| success = false; error = "Invalid request body" |}
                    )
                else
                    // ---- HMAC VERIFICATION ----
                    let rawData = req.id + req.hwid + req.nonce
                    let expectedSig = computeHmac rawData

                    if not (expectedSig.Equals(req.sig, StringComparison.OrdinalIgnoreCase)) then
                        ctx.Response.StatusCode <- 401
                        do! ctx.Response.WriteAsJsonAsync(
                            {| success = false; error = "Invalid signature" |}
                        )
                    else
                        // ---- FIREBASE FETCH ----
                        let! appJson =
                            getJson($"{firebaseDbUrl}/app.json")

                        let! userJson =
                            getJson($"{firebaseDbUrl}/users/{req.id}.json")

                        if userJson.ValueKind = JsonValueKind.Null then
                            ctx.Response.StatusCode <- 404
                            do! ctx.Response.WriteAsJsonAsync(
                                {| success = false; error = "User not found" |}
                            )
                        else
                            do! ctx.Response.WriteAsJsonAsync(
                                {| success = true
                                   app = appJson
                                   user = userJson |}
                            )
            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = ex.Message |}
                )
        }
    )
) |> ignore

// ================= RUN =================

app.Run()
