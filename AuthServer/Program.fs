open System
open System.Collections.Concurrent
open System.Text.Json
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting

// ---------------- CONFIG ----------------

let REQUIRED_VERSION = "1.2.0"
let PASSWORD = "secret123"
let MAX_ATTEMPTS = 3
let BAN_SECONDS = 86400L // 1 day

// ---------------- MODELS ----------------

type LoginRequest =
    { hwid: string
      version: string
      password: string }

// ---------------- STORAGE ----------------

type HwidState =
    { mutable count: int
      mutable banUntil: int64 }

let store = ConcurrentDictionary<string, HwidState>()

let unixNow () =
    DateTimeOffset.UtcNow.ToUnixTimeSeconds()

// ---------------- APP ----------------

let builder = WebApplication.CreateBuilder()
let app = builder.Build()

app.MapPost("/login",
    Func<HttpContext, Task<IResult>>(fun ctx ->
        task {

            let! req =
                JsonSerializer.DeserializeAsync<LoginRequest>(
                    ctx.Request.Body,
                    JsonSerializerOptions(PropertyNameCaseInsensitive = true)
                )

            if isNull req then
                return Results.BadRequest()

            // ---- VERSION CHECK ----
            if req.version <> REQUIRED_VERSION then
                return Results.Json(
                    {| success = false
                       reason = "update_required"
                       requiredVersion = REQUIRED_VERSION |},
                    statusCode = 426
                )

            let state =
                store.GetOrAdd(
                    req.hwid,
                    fun _ -> { count = 0; banUntil = 0L }
                )

            // ---- BAN CHECK ----
            let now = unixNow ()
            if state.banUntil > now then
                return Results.Json(
                    {| success = false
                       reason = "banned"
                       retryAfter = state.banUntil |},
                    statusCode = 403
                )

            // ---- PASSWORD CHECK ----
            if req.password <> PASSWORD then
                state.count <- state.count + 1

                if state.count >= MAX_ATTEMPTS then
                    state.banUntil <- now + BAN_SECONDS

                return Results.Json(
                    {| success = false
                       attemptsLeft = max 0 (MAX_ATTEMPTS - state.count) |},
                    statusCode = 401
                )

            // ---- SUCCESS ----
            state.count <- 0
            state.banUntil <- 0L

            return Results.Ok(
                {| success = true |}
            )
        }
    )
)
|> ignore

app.Run()
