open System
open System.Net.Http
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting

// ---------------- CONFIG ----------------

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")

// DO NOT CRASH THE APP
let firebaseDbUrl =
    if String.IsNullOrWhiteSpace(firebaseDbUrl) then
        ""
    else firebaseDbUrl.TrimEnd('/')

// ---------------- APP ----------------

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

let http = new HttpClient()

let getJson (url: string) =
    task {
        let! res = http.GetAsync(url)
        let! txt = res.Content.ReadAsStringAsync()
        return JsonDocument.Parse(txt).RootElement
    }

// ---------------- ROOT (TEST) ----------------

app.MapGet("/", fun () ->
    Results.Ok("AuthServer running")
) |> ignore

// ---------------- API ----------------

app.MapPost("/hmx/oauth", fun (ctx: HttpContext) ->
    task {
        try
            let! body =
                JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body)

            if not (body.TryGetProperty("id") |> fst) then
                return Results.BadRequest(
                    {| success = false; error = "id missing" |}
                )
            else
                let id = body.GetProperty("id").GetString()

                let! appJson =
                    getJson($"{firebaseDbUrl}/app.json")

                let! userJson =
                    getJson($"{firebaseDbUrl}/users/{id}.json")

                let exists =
                    userJson.ValueKind <> JsonValueKind.Null

                return Results.Ok(
                    {| success = exists
                       app = appJson
                       user = if exists then userJson else null |}
                )
        with ex ->
            return Results.Problem(ex.Message)
    }
) |> ignore

app.Run()
