open System
open System.Net.Http
open System.Net.Http.Json
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting

// ---------------- CONFIG ----------------

let firebaseDbUrl =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")
    |> fun v -> if String.IsNullOrWhiteSpace(v) then "" else v.TrimEnd('/')

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

// ---------------- ROOT ----------------

app.MapGet(
    "/",
    Func<IResult>(fun () ->
        Results.Ok("AuthServer running")
    )
)
|> ignore

// ---------------- POST /hmx/oauth ----------------

app.MapPost(
    "/hmx/oauth",
    RequestDelegate(fun ctx ->
        task {
            try
                let! body =
                    ctx.Request.ReadFromJsonAsync<JsonElement>()

                let hasId, _ = body.TryGetProperty("id")

                if not hasId then
                    ctx.Response.StatusCode <- 400
                    do! ctx.Response.WriteAsJsonAsync(
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

                    do! ctx.Response.WriteAsJsonAsync(
                        {| success = exists
                           app = appJson
                           user =
                               if exists then box userJson else null |}
                    )
            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = ex.Message |}
                )
        }
    )
)
|> ignore

app.Run()
