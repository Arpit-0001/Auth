namespace AuthServer

open System
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection

open FirebaseAdmin
open FirebaseAdmin.Auth
open Google.Apis.Auth.OAuth2

module Program =

    let mutable firebaseInitialized = false

    let tryInitFirebase () =
        if not firebaseInitialized then
            let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")

            if String.IsNullOrWhiteSpace(json) then
                false
            else
                let credential = GoogleCredential.FromJson(json)
                FirebaseApp.Create(
                    AppOptions(
                        Credential = credential
                    )
                ) |> ignore

                firebaseInitialized <- true
                true
        else
            true

    [<EntryPoint>]
    let main args =
        let builder = WebApplication.CreateBuilder(args)

        builder.Services.AddRouting() |> ignore

        let app = builder.Build()

        // ---------- ROUTES ----------

        app.MapGet("/", Func<string>(fun () ->
            "AuthServer running"
        )) |> ignore

        app.MapPost("/verify",
            Func<HttpContext, Threading.Tasks.Task>(fun ctx ->
                task {
                    if not (tryInitFirebase ()) then
                        ctx.Response.StatusCode <- 500
                        do! ctx.Response.WriteAsync("Firebase not configured")
                    else
                        let! body = JsonDocument.ParseAsync(ctx.Request.Body)
                        let token =
                            body.RootElement.GetProperty("token").GetString()

                        let! decoded =
                            FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token)

                        let result =
                            {| uid = decoded.Uid |}

                        ctx.Response.ContentType <- "application/json"
                        do! ctx.Response.WriteAsync(
                            JsonSerializer.Serialize(result)
                        )
                }
            )
        ) |> ignore

        app.Run()
        0
