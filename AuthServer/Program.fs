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
        logger.LogCritical("FIREBASE_SERVICE_ACCOUNT is missing! API will return 500 on /verify.")
        false
    else
        try
            let credential = GoogleCredential.FromJson(json)
            let options = AppOptions(Credential = credential)
            if FirebaseApp.DefaultInstance <> null then
                FirebaseApp.Delete(FirebaseApp.DefaultInstance)
            FirebaseApp.Create(options) |> ignore
            logger.LogInformation("Firebase Admin SDK initialized successfully.")
            true
        with ex ->
            logger.LogCritical(ex, "Failed to initialize Firebase with provided credentials.")
            false

[<EntryPoint>]
let main args =
    let builder = WebApplication.CreateBuilder(args)

    builder.Logging.AddConsole() |> ignore
    builder.Services.AddEndpointsApiExplorer() |> ignore
    builder.Services.AddSwaggerGen() |> ignore

    let app = builder.Build()
    let logger = app.Logger

    let firebaseReady = tryInitializeFirebase logger

    if app.Environment.IsDevelopment() then
        app.UseSwagger() |> ignore
        app.UseSwaggerUI() |> ignore

    app.UseHttpsRedirection() |> ignore

    // Health check endpoint
    app.MapGet("/", fun () -> "Firebase Auth API is running! POST to /verify with {\"idToken\": \"...\"}") |> ignore

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

                if not firebaseReady || FirebaseApp.DefaultInstance = null then
                    return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Firebase not initialized – check server logs" |}; r

                let! decoded = FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(idToken)

                let email = if decoded.Claims.ContainsKey("email") then decoded.Claims["email"] :?> string else null
                let emailVerified = if decoded.Claims.ContainsKey("email_verified") then decoded.Claims["email_verified"] :?> bool else false

                return Results.Ok({|
                    uid = decoded.Uid
                    email = email
                    email_verified = emailVerified
                    verified = true
                |})
            with
            | :? FirebaseAuthException as ex ->
                logger.LogWarning(ex, "Token verification failed")
                return Results.Unauthorized() |> fun r -> r.Value <- {| error = ex.Message; verified = false |}; r
            | ex ->
                logger.LogError(ex, "Unexpected error")
                return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Server error" |}; r
        }
    )) |> ignore

    logger.LogInformation("API starting up...")
    app.Run()
    0
