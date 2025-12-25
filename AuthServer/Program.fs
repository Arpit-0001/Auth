open System
open System.Net.Http
open System.Text
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection

// ---------- Models ----------
type OAuthRequest =
    { id: string }

type ApiResponse =
    { success: bool
      app: JsonElement
      user: JsonElement option
      error: string option }

// ---------- App ----------
let builder = WebApplication.CreateBuilder()
builder.Services.AddRouting()
builder.Services.AddEndpointsApiExplorer()

let app = builder.Build()

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")

if String.IsNullOrWhiteSpace(firebaseDbUrl) then
    failwith "FIREBASE_DB_URL environment variable not set"

// ---------- Helpers ----------
let httpClient = new HttpClient()

let getJson (url: string) =
    task {
        let! res = httpClient.GetAsync(url)
        let! body = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(body).RootElement
    }

// ---------- Endpoint ----------
app.MapPost("/hmx/oauth", fun (ctx: HttpContext) ->
    task {
        try
            let! req =
                JsonSerializer.DeserializeAsync<OAuthRequest>(
                    ctx.Request.Body,
                    JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                )

            if isNull req || String.IsNullOrWhiteSpace(req.id) then
                ctx.Response.StatusCode <- 400
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = "Invalid ID" |}
                )
            else
                // Fetch app config
                let! appJson =
                    getJson($"{firebaseDbUrl}/app.json")

                // Fetch user
                let! userJson =
                    getJson($"{firebaseDbUrl}/users/{req.id}.json")

                let userExists =
                    userJson.ValueKind <> JsonValueKind.Null

                let response =
                    { success = userExists
                      app = appJson
                      user =
                          if userExists then Some userJson else None
                      error =
                          if userExists then None
                          else Some "User not found" }

                do! ctx.Response.WriteAsJsonAsync(response)
        with ex
            ctx.Response.StatusCode <- 500
            do! ctx.Response.WriteAsJsonAsync(
                {| success = false; error = ex.Message |}
            )
    }
)

app.Run()
