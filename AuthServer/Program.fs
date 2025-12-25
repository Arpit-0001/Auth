namespace AuthServer

open System
open System.Text.Json
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open FirebaseAdmin
open Google.Apis.Auth.OAuth2
open Google.Cloud.Firestore

// --------------------
// Models
// --------------------
type AuthRequest =
    { accountId: string
      hwid: string }

// --------------------
// Firebase Init (Safe)
// --------------------
module Firebase =

    let tryInit (logger: ILogger) =
        let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")

        if String.IsNullOrWhiteSpace(json) then
            logger.LogCritical("FIREBASE_SERVICE_ACCOUNT is missing or empty! Server will run but /auth will fail.")
            None
        else
            try
                logger.LogInformation("Initializing Firebase with service account...")
                let credential = GoogleCredential.FromJson(json)
                let options = AppOptions(Credential = credential)

                if FirebaseApp.DefaultInstance <> null then
                    FirebaseApp.Delete(FirebaseApp.DefaultInstance)

                let app = FirebaseApp.Create(options)
                logger.LogInformation("Firebase initialized successfully. Project ID: {ProjectId}", app.Options.ProjectId)
                Some app
            with ex ->
                logger.LogCritical(ex, "Failed to initialize Firebase – INVALID JSON or credentials! Check FIREBASE_SERVICE_ACCOUNT value.")
                None

// --------------------
// Program
// --------------------
module Program =

    [<EntryPoint>]
    let main args =

        let builder = WebApplication.CreateBuilder(args)

        // Better logging
        builder.Logging.AddConsole() |> ignore

        let app = builder.Build()
        let logger = app.Logger

        let firebaseAppOpt = Firebase.tryInit logger

        let getDb () =
            match firebaseAppOpt with
            | Some firebaseApp ->
                let projectId = firebaseApp.Options.ProjectId
                Some (FirestoreDb.Create(projectId))
            | None -> None

        // Health check root
        app.MapGet("/", fun () ->
            if firebaseAppOpt.IsSome then
                "Auth API running! Firebase OK. POST to /auth"
            else
                "API running but Firebase FAILED – check logs!"
        ) |> ignore

        // Your original /auth endpoint (with safety)
        app.MapPost("/auth", Func<HttpContext, Task<IResult>>(fun ctx ->
            task {
                try
                    use reader = new StreamReader(ctx.Request.Body)
                    let! bodyStr = reader.ReadToEndAsync()

                    if String.IsNullOrWhiteSpace(bodyStr) then
                        return Results.BadRequest("Empty body")

                    let request = JsonSerializer.Deserialize<AuthRequest>(bodyStr)

                    match getDb() with
                    | None ->
                        return Results.StatusCode(500) |> fun r -> r.Value <- "Firebase not initialized"; r
                    | Some db ->
                        let! appSnap = db.Collection("app").Document("config").GetSnapshotAsync()

                        let! userSnap = db.Collection("users").Document(request.accountId).GetSnapshotAsync()

                        if not userSnap.Exists then
                            return Results.Unauthorized() |> fun r -> r.Value <- "Unauthorized"; r
                        else
                            let appJson = JsonSerializer.Serialize(appSnap.ToDictionary())
                            let userJson = JsonSerializer.Serialize(userSnap.ToDictionary())

                            let response = {| app = JsonDocument.Parse(appJson).RootElement; user = JsonDocument.Parse(userJson).RootElement |}

                            return Results.Ok(response)
                with ex ->
                    logger.LogError(ex, "Error in /auth handler")
                    return Results.StatusCode(500) |> fun r -> r.Value <- "Server error"; r
            }
        )) |> ignore

        logger.LogInformation("Auth API starting...")
        app.Run()

        0
