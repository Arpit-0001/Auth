open System
open System.IO
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open FirebaseAdmin
open Google.Apis.Auth.OAuth2
open FirebaseAdmin.Auth

let initializeFirebase (logger: ILogger) =
    let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")
    if String.IsNullOrEmpty(json) then
        logger.LogError("FIREBASE_SERVICE_ACCOUNT environment variable is missing or empty. Cannot initialize Firebase.")
        // Don't failwith – let the app start so you can see logs
    else
        try
            let credential = GoogleCredential.FromJson(json)
            let options = AppOptions(Credential = credential)
            if FirebaseApp.DefaultInstance = null then
                FirebaseApp.Create(options) |> ignore
                logger.LogInformation("Firebase Admin SDK initialized successfully.")
            else
                logger.LogInformation("FirebaseApp already initialized.")
        with ex ->
            logger.LogError(ex, "Failed to initialize Firebase Admin SDK.")

[<EntryPoint>]
let main args =
    let builder = WebApplication.CreateBuilder(args)

    // Add logging and services
    builder.Logging.ClearProviders() |> ignore
    builder.Logging.AddConsole() |> ignore
    builder.Services.AddEndpointsApiExplorer() |> ignore
    builder.Services.AddSwaggerGen() |> ignore

    let app = builder.Build()
    let logger = app.Logger

    // Initialize Firebase (with better logging)
    initializeFirebase logger

    if app.Environment.IsDevelopment() then
        app.UseSwagger() |> ignore
        app.UseSwaggerUI() |> ignore

    app.UseHttpsRedirection() |> ignore

    // POST /verify
    app.MapPost("/verify", Func<HttpContext, Task<IResult>>(fun context ->
        task {
            try
                use reader = new StreamReader(context.Request.Body)
                let! body = reader.ReadToEndAsync()

                if String.IsNullOrWhiteSpace(body) then
                    return Results.BadRequest({| error = "Request body is empty" |})

                let jsonDoc = JsonDocument.Parse(body)
                if not (jsonDoc.RootElement.TryGetProperty("idToken", &let prop) && prop.ValueKind = JsonValueKind.String) then
                    return Results.BadRequest({| error = "idToken is required in JSON body" |})

                let idToken = jsonDoc.RootElement.GetProperty("idToken").GetString()

                // Check if Firebase is initialized
                if FirebaseApp.DefaultInstance = null then
                    return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Firebase not initialized – check server logs" |}; r

                let! decodedToken = FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(idToken)

                let response =
                    {|
                        uid = decodedToken.Uid
                        email = if decodedToken.Claims.TryGetValue("email") then decodedToken.Claims["email"] :?> string else null
                        email_verified = if decodedToken.Claims.TryGetValue("email_verified") then decodedToken.Claims["email_verified"] :?> bool else false
                        verified = true
                    |}

                return Results.Ok(response)
            with
            | :? FirebaseAuthException as ex ->
                logger.LogWarning(ex, "Invalid Firebase token")
                return Results.Unauthorized() |> fun r -> r.Value <- {| error = ex.Message; verified = false |}; r
            | ex ->
                logger.LogError(ex, "Unexpected error during token verification")
                return Results.StatusCode(500) |> fun r -> r.Value <- {| error = "Internal server error" |}; r
        }
    ))
    |> ignore

    app.Run()

    0
