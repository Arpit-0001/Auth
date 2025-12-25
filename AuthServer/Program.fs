open System
open System.Net.Http
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection
open System.Threading.Tasks

// ------------------ MODELS ------------------

type OAuthRequest =
    { id: string }

type ApiResponse =
    { success: bool
      app: JsonElement
      user: JsonElement option
      error: string option }

// ------------------ APP SETUP ------------------

let builder = WebApplication.CreateBuilder()

builder.Services.AddRouting() |> ignore
builder.Services.AddEndpointsApiExplorer() |> ignore

let app = builder.Build()

// ⭐ REQUIRED — fixes 404
app.UseRouting()

// ------------------ ENV ------------------

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")

if String.IsNullOrWhiteSpace(firebaseDbUrl) then
    failwith "FIREBASE_DB_URL environment variable not set"

// ------------------ HTTP ------------------

let httpClient = new HttpClient()

let getJson (url: string) =
    task {
        let! response = httpClient.GetAsync(url)
        let! body = response.Content.ReadAsStringAsync()
        return JsonDocument.Parse(body).RootElement
    }

// ------------------ ENDPOINT ------------------

app.MapPost(
    "/hmx/oauth",
    Func<HttpContext, Task>(fun ctx ->
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
                    let! appJson =
                        getJson($"{firebaseDbUrl}/app.json")

                    let! userJson =
                        getJson($"{firebaseDbUrl}/users/{req.id}.json")

                    let userExists =
                        userJson.ValueKind <> JsonValueKind.Null

                    let response: ApiResponse =
                        { success = userExists
                          app = appJson
                          user =
                              if userExists then Some userJson else None
                          error =
                              if userExists then None
                              else Some "User not found" }

                    do! ctx.Response.WriteAsJsonAsync(response)
            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = ex.Message |}
                )
        }
    )
) |> ignore

app.Run()
