open System
open System.Net.Http
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

// Helper function for GET requests (returning JSON)
let getJson (url: string) =
    async {
        let! res = http.GetAsync(url) |> Async.AwaitTask
        let! txt = res.Content.ReadAsStringAsync() |> Async.AwaitTask
        return JsonDocument.Parse(txt).RootElement
    }

// Helper function for PUT requests (sending JSON)
let putJson (url: string) (body: obj) =
    async {
        let json = JsonSerializer.Serialize(body)
        let content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        do! http.PutAsync(url, content) |> Async.AwaitTask
    }

// ---------------- ROOT ----------------
app.MapGet(
    "/",
    Func<IResult>(fun () ->
        Results.Ok("AuthServer running")
    )
) |> ignore

// ---------------- POST /hmx/oauth ----------------
app.MapPost(
    "/hmx/oauth",
    RequestDelegate(fun ctx ->
        async {
            try
                let! body =
                    JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body) |> Async.AwaitTask

                // Check if 'id' property is provided in the request
                if not (body.TryGetProperty("id") |> fst) then
                    ctx.Response.StatusCode <- 400
                    do! ctx.Response.WriteAsJsonAsync(
                        {| success = false; error = "id missing" |}
                    )
                else
                    let id = body.GetProperty("id").GetString()

                    // Get App version from database
                    let! appJson =
                        getJson($"{firebaseDbUrl}/app.json")
                    
                    let serverVersion = appJson.GetProperty("version").GetDouble()

                    // Get User data from database
                    let! userJson =
                        getJson($"{firebaseDbUrl}/users/{id}.json")

                    // Check if user exists
                    let exists =
                        userJson.ValueKind <> JsonValueKind.Null

                    if not exists then
                        do! ctx.Response.WriteAsJsonAsync(
                            {| success = false; error = "Invalid user ID" |}
                        )
                    else
                        let user = userJson
                        let hwid = body.GetProperty("hwid").GetString()
                        let version = body.GetProperty("version").GetDouble()

                        // 1. Check version mismatch
                        if version < serverVersion then
                            ctx.Response.StatusCode <- 426 // Upgrade Required
                            do! ctx.Response.WriteAsJsonAsync(
                                {| success = false; reason = "VERSION_MISMATCH"; requiredVersion = serverVersion |}
                            )
                        else
                            // 2. Check if user has valid features and is allowed to login
                            let featuresEnabled = appJson.GetProperty("features")
                            let hotmailEnabled = featuresEnabled.GetProperty("hotmail_inbox").GetProperty("enabled").GetBoolean()

                            if not hotmailEnabled && user.GetProperty("hotmail_inbox").GetBoolean() then
                                ctx.Response.StatusCode <- 403 // Forbidden: Feature not enabled
                                do! ctx.Response.WriteAsJsonAsync(
                                    {| success = false; reason = "FEATURE_NOT_ENABLED"; feature = "hotmail_inbox" |}
                                )
                            else
                                // 3. Check HWID Attempts
                                let! hwidJson = getJson $"{firebaseDbUrl}/hwid_attempts/{hwid}.json"

                                let mutable count = 0
                                let mutable banUntil = 0L
                                if hwidJson.ValueKind <> JsonValueKind.Null then
                                    let countProp = hwidJson.GetProperty("count").GetInt32()
                                    let banUntilProp = hwidJson.GetProperty("banUntil").GetInt64()

                                    count <- countProp
                                    banUntil <- banUntilProp

                                let now = DateTimeOffset.UtcNow.ToUnixTimeSeconds()

                                if banUntil > now then
                                    ctx.Response.StatusCode <- 403 // Forbidden: HWID is banned
                                    do! ctx.Response.WriteAsJsonAsync(
                                        {| success = false; reason = "HWID_BANNED"; retryAfter = banUntil - now |}
                                    )
                                else
                                    // 4. Increment the fail count and possibly ban the HWID
                                    if count >= 3 then
                                        let newBanUntil = now + 86400L // Ban for 1 day
                                        do!
                                            putJson $"{firebaseDbUrl}/hwid_attempts/{hwid}.json"
                                            {| count = count; lastFail = now; banUntil = newBanUntil |}
                                        ctx.Response.StatusCode <- 403
                                        do! ctx.Response.WriteAsJsonAsync(
                                            {| success = false; reason = "HWID_BANNED"; retryAfter = newBanUntil - now |}
                                        )
                                    else
                                        // Update attempt count
                                        do!
                                            putJson $"{firebaseDbUrl}/hwid_attempts/{hwid}.json"
                                            {| count = count + 1; lastFail = now; banUntil = 0L |}

                                        // 5. Send successful login response with user data
                                        do! ctx.Response.WriteAsJsonAsync(
                                            {| success = true; user = userJson |}
                                        )
            with ex ->
                ctx.Response.StatusCode <- 500
                do! ctx.Response.WriteAsJsonAsync(
                    {| success = false; error = ex.Message |}
                )
        }
    )
) |> ignore

app.Run()


