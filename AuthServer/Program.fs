open System
open System.IO
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open FirebaseAdmin
open Google.Apis.Auth.OAuth2
open FirebaseAdmin.Auth

let tryInitializeFirebase (logger: ILogger) =
    let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")
    if String.IsNullOrWhiteSpace(json) then
        logger.LogCritical("FIREBASE_SERVICE_ACCOUNT is EMPTY or MISSING! Fix the env var.")
        false
    else
        try
            logger.LogInformation("Attempting to parse Firebase service account JSON...")
            let credential = GoogleCredential.FromJson(json)
            let options = AppOptions(Credential = credential)
            if FirebaseApp.DefaultInstance <> null then
                FirebaseApp.Delete(FirebaseApp.DefaultInstance)
            FirebaseApp.Create(options) |> ignore
            logger.LogInformation("Firebase Admin SDK initialized SUCCESSFULLY!")
            true
        with ex ->
            logger.LogCritical(ex, "INVALID Firebase JSON or credentials! Check the env var value – it must be the FULL service account JSON.")
            false

[<EntryPoint>]
let main args =
    let builder = WebApplication.CreateBuilder(args)

    // Enable detailed console logging
    builder.Logging.AddConsole() |> ignore
    builder.Logging.SetMinimumLevel(LogLevel.Information) |> ignore

    builder.Services.AddEndpointsApiExplorer() |> ignore
    builder.Services.AddSwaggerGen() |> ignore

    let app = builder.Build()
    let logger = app.Logger

    let firebaseReady = tryInitializeFirebase logger

    if app.Environment.IsDevelopment() then
        app.UseSwagger() |> ignore
        app.UseSwaggerUI() |> ignore

    app.UseHttpsRedirection() |> ignore

    // Root health check – visit your URL to see if alive
    app.MapGet("/", fun () ->
        if firebaseReady then
            "Firebase Auth API running! Firebase OK. POST to /verify with {\"idToken\": \"...\"}"
        else
            "API running but Firebase FAILED – check logs!"
    ) |> ignore

    // Verify endpoint
    app.MapPost("/verify", Func<HttpContext, Task<IResult>>(fun context ->
        task {
            try
                use reader = new StreamReader(context.Request.Body)
                let! body = reader.ReadToEndAsync()
                if String.IsNullOrWhiteSpace(body) then
                    return Results.BadRequest({| error = "Empty body" |})

                let doc = JsonDocument.Parse(body)
                if not (doc.RootElement.TryGetProperty("idToken")) then
                    return Results.BadRequest({| error = "Missing idToken" |})

                let idToken = doc.RootElement.GetProperty("idToken").GetString()

                if not firebaseReady then
                    return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Firebase init failed – check server logs" |}; r

                let! decoded = FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(idToken)

                return Results.Ok({|
                    uid = decoded.Uid
                    email = if decoded.Claims.ContainsKey("email") then decoded.Claims["email"] :?> string else null
                    email_verified = if decoded.Claims.ContainsKey("email_verified") then decoded.Claims["email_verified"] :?> bool else false
                    verified = true
                |})
            with
            | :? FirebaseAuthException as ex ->
                logger.LogWarning(ex, "Invalid token")
                return Results.Unauthorized() |> fun r -> r.Value <- {| error = ex.Message; verified = false |}; r
            | ex ->
                logger.LogError(ex, "Unexpected error")
                return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Server error" |}; r
        }
    )) |> ignore

    logger.LogInformation("Starting API on port {Port}...", Environment.GetEnvironmentVariable("PORT") ?? "80")
    app.Run()

    0
