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

app.MapGet("/", fun () ->
    Results.Text("AuthServer running")
) |> ignore

// ================= API =================

open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection
open System.Text.Json
open System.Threading.Tasks

app.MapPost("/login",
    Func<HttpContext, Task<IResult>>(fun ctx ->
        task {

            let! body =
                JsonSerializer.DeserializeAsync<LoginRequest>(
                    ctx.Request.Body,
                    JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                )

            let hwid = body.hwid
            let version = body.version

            // ---- VERSION CHECK ----
            if version <> ServerConfig.RequiredVersion then
                return Results.Json(
                    {| success = false
                       reason = "update_required"
                       requiredVersion = ServerConfig.RequiredVersion |},
                    statusCode = 426
                )

            // ---- HWID CHECK ----
            let state = getHwidState hwid

            if state.banUntil > DateTimeOffset.UtcNow.ToUnixTimeSeconds() then
                return Results.Json(
                    {| success = false
                       reason = "banned"
                       retryAfter = state.banUntil |},
                    statusCode = 403
                )

            if body.password <> ServerConfig.Password then
                let updated = incrementFail hwid state
                if updated.count >= 3 then
                    banHwid hwid
                return Results.Json(
                    {| success = false
                       reason = "invalid_credentials"
                       attemptsLeft = max 0 (3 - updated.count) |},
                    statusCode = 401
                )

            resetFails hwid

            return Results.Ok(
                {| success = true |}
            )
        }
    )
)


// ================= RUN =================

app.Run()
