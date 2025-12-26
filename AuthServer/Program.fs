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
app.MapPost("/hmx/oauth", Func<HttpContext, Task<IResult>>(fun (ctx: HttpContext) ->
    task {
        try
            use sr = new System.IO.StreamReader(ctx.Request.Body)
            let! raw = sr.ReadToEndAsync()
            let body: JsonNode = JsonNode.Parse(raw)
            
            if isNull body || isNull body["id"] then
                ctx.Response.StatusCode <- 400
                return Results.Json(
                    {| success = false; error = "id missing" |},
                    statusCode = 400
                )
            elif isNull body["hwid"] then
                ctx.Response.StatusCode <- 400
                return Results.Json(
                    {| success = false; error = "hwid missing" |},
                    statusCode = 400
                )
            elif isNull body["version"] then
                ctx.Response.StatusCode <- 400
                return Results.Json(
                    {| success = false; error = "version missing" |},
                    statusCode = 400
                )
            else
                let id = body["id"].GetValue<string>()
                let hwid = body["hwid"].GetValue<string>()
                let clientVersion = body["version"].GetValue<float>()
                
                let! appCfg = getJson($"{firebaseDbUrl}/app.json")
                let serverVersion = appCfg["version"].GetValue<float>()
                
                if clientVersion <> serverVersion then
                    return Results.Json(
                        {| success = false
                           reason = "VERSION_MISMATCH"
                           requiredVersion = serverVersion |},
                        statusCode = 426
                    )
                else
                    let! user = getJson($"{firebaseDbUrl}/users/{id}.json")
                    if isNull user then
                        return Results.Json(
                            {| success = false; reason = "INVALID_USER" |},
                            statusCode = 401
                        )
                    else
                        let! attempt = getJson($"{firebaseDbUrl}/hwid_attempts/{hwid}.json")
                        let now = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                        let count = if isNull attempt then 0 else attempt["count"].GetValue<int>()
                        let banUntil = if isNull attempt then 0L else attempt["banUntil"].GetValue<int64>()
                        
                        if banUntil > now then
                            return Results.Json(
                                {| success = false
                                   reason = "HWID_BANNED"
                                   retryAfter = banUntil - now |},
                                statusCode = 403
                            )
                        elif count >= 3 then
                            let ban = now + 86400L
                            let banJson = JsonNode.Parse(
                                $"""{{ "count": {count}, "lastFail": {now}, "banUntil": {ban} }}""")
                            do! putJson $"{firebaseDbUrl}/hwid_attempts/{hwid}.json" banJson
                            return Results.Json(
                                {| success = false
                                   reason = "HWID_BANNED"
                                   retryAfter = 86400 |},
                                statusCode = 403
                            )
                        else
                            let attemptJson = JsonNode.Parse(
                                $"""{{ "count": {count + 1}, "lastFail": {now}, "banUntil": 0 }}""")
                            do! putJson $"{firebaseDbUrl}/hwid_attempts/{hwid}.json" attemptJson
                            return Results.Json({| success = true |})
        with ex ->
            return Results.Json(
                {| success = false; error = ex.Message |},
                statusCode = 500
            )
    } :> Task<IResult>
)) |> ignore

app.Run()
