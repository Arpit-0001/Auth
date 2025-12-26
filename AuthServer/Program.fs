open System
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading.Tasks
open System.Text.Json.Nodes
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

// ---------------- HELPERS (TASK ONLY) ----------------
let getJson (url: string) = task {
    let! res = http.GetAsync(url)
    let! txt = res.Content.ReadAsStringAsync()
    return JsonNode.Parse(txt)
}

let putJson (url: string) (body: JsonNode) = task {
    let json = body.ToJsonString()
    let content = new StringContent(json, Encoding.UTF8, "application/json")
    let! _ = http.PutAsync(url, content)
    return ()
}

// ---------------- ROOT ----------------
app.MapGet("/", fun () ->
    Results.Ok("AuthServer running")
) |> ignore

// ---------------- POST /hmx/oauth ----------------
app.MapPost(
    "/hmx/oauth",
    Func<HttpContext, Task>(fun ctx ->
        task {

            try
                use sr = new System.IO.StreamReader(ctx.Request.Body)
                let! raw = sr.ReadToEndAsync()
                let body: JsonNode = JsonNode.Parse(raw)

                if isNull body || isNull body["id"] then
                    ctx.Response.StatusCode <- 400
                    do! ctx.Response.WriteAsJsonAsync(
                        {| success = false; error = "id missing" |}
                    )
                    return ()
                else
                    let id = body["id"].GetValue<string>()
                    let hwid = body["hwid"].GetValue<string>()
                    let clientVersion = body.["version"].GetValue<float>()

                    let! appCfg = getJson($"{firebaseDbUrl}/app.json") : Task<JsonNode>
                    let serverVersion = appCfg.["version"].GetValue<float>()

                    if clientVersion <> serverVersion then
                        ctx.Response.StatusCode <- 426
                        do! ctx.Response.WriteAsJsonAsync(
                            {| success = false
                               reason = "VERSION_MISMATCH"
                               requiredVersion = serverVersion |}
                        )
                        return ()
                    else
                        let! user = getJson($"{firebaseDbUrl}/users/{id}.json")

                        if isNull user then
                            ctx.Response.StatusCode <- 401
                            do! ctx.Response.WriteAsJsonAsync(
                                {| success = false; reason = "INVALID_USER" |}
                            )
                            return ()
                        else
                            let! attempt =
                                getJson($"{firebaseDbUrl}/hwid_attempts/{hwid}.json")
                                : Task<JsonNode>

                            let now = DateTimeOffset.UtcNow.ToUnixTimeSeconds()

                            let count =
                                if isNull attempt then 0
                                else attempt["count"].GetValue<int>()


                            let banUntil =
                                if isNull attempt then 0L
                                else attempt["banUntil"].GetValue<int64>()

                            if banUntil > now then
                                ctx.Response.StatusCode <- 403
                                do! ctx.Response.WriteAsJsonAsync(
                                    {| success = false
                                       reason = "HWID_BANNED"
                                       retryAfter = banUntil - now |}
                                )
                                return ()
                            else
                                if count >= 3 then
                                    let ban = now + 86400L
                                    do!
                                        putJson
                                            $"{firebaseDbUrl}/hwid_attempts/{hwid}.json"
                                            (JsonNode.Parse(
                                                $"""{{ "count": {count}, "lastFail": {now}, "banUntil": {ban} }}"""
                                            ))

                                    ctx.Response.StatusCode <- 403
                                    do! ctx.Response.WriteAsJsonAsync(
                                        {| success = false
                                           reason = "HWID_BANNED"
                                           retryAfter = 86400 |}
                                    )
                                    return ()
                                else
                                    do!
                                        putJson
                                            $"{firebaseDbUrl}/hwid_attempts/{hwid}.json"
                                            (JsonNode.Parse(
                                                $"""{{ "count": {count + 1}, "lastFail": {now}, "banUntil": 0 }}"""
                                            ))

                                    do! ctx.Response.WriteAsJsonAsync({| success = true |})
                                    return()

            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = ex.Message |}
                )
                return ()
        } :> Task
    )
)
|> ignore

app.Run()
