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

let secretKey =
    match Environment.GetEnvironmentVariable("SECRET_KEY") with
    | null | "" -> "HMX_BY_MR_ARPIT_120"
    | v -> v

// ================= SECURITY =================

let computeHmac (input: string) =
    use hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey))
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
    "AuthServer running"
) |> ignore

// ================= API =================

app.MapPost(
    "/hmx/oauth",
    RequestDelegate(fun ctx ->
        task {
            ctx.Response.ContentType <- "application/json"

            try
                let! reqOpt =
                    JsonSerializer.DeserializeAsync<OAuthRequest option>(
                        ctx.Request.Body,
                        JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                    )

                match reqOpt with
                | None ->
                    ctx.Response.StatusCode <- 400
                    do! ctx.Response.WriteAsync("""{"success":false,"error":"Invalid JSON"}""")

                | Some req ->
                    let raw = req.id + req.hwid + req.version + req.nonce
                    let expectedSig = computeHmac raw

                    if not (String.Equals(expectedSig, req.sigValue, StringComparison.OrdinalIgnoreCase)) then
                        ctx.Response.StatusCode <- 401
                        do! ctx.Response.WriteAsync("""{"success":false,"error":"Invalid signature"}""")
                    else
                        let! appJson = getJson $"{firebaseDbUrl}/app.json"
                        let! userJson = getJson $"{firebaseDbUrl}/users/{req.id}.json"

                        if userJson.ValueKind = JsonValueKind.Null then
                            ctx.Response.StatusCode <- 404
                            do! ctx.Response.WriteAsync("""{"success":false,"error":"User not found"}""")
                        else
                            let response =
                                JsonSerializer.Serialize(
                                    {| success = true
                                       app = appJson
                                       user = userJson |}
                                )

                            ctx.Response.StatusCode <- 200
                            do! ctx.Response.WriteAsync(response)

            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsync(
                    JsonSerializer.Serialize(
                        {| success = false; error = ex.Message |}
                    )
                )
        }
    )
) |> ignore

// ================= RUN =================

app.Run()
