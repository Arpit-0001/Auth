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

    /// Initialize Firebase using ENV variable
    let initFirebase () =
        if FirebaseApp.DefaultInstance = null then
            let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")

            if String.IsNullOrWhiteSpace(json) then
                failwith "FIREBASE_SERVICE_ACCOUNT env variable not set"

            let credential =
                GoogleCredential.FromJson(json)

            FirebaseApp.Create(
                AppOptions(
                    Credential = credential
                )
            )
            |> ignore

    [<EntryPoint>]
    let main args =
        // ---- BUILD WEB APP ----
        let builder = WebApplication.CreateBuilder(args)

        builder.Services.AddRouting() |> ignore

        let app = builder.Build()

        // ---- INIT FIREBASE ----
        initFirebase ()

        // ---- ROUTES ----

        app.MapGet("/", Func<string>(fun () ->
            "AuthServer running OK"
        )) |> ignore

        // Verify Firebase ID Token
        app.MapPost("/verify", Func<HttpContext, Threading.Tasks.Task>(fun ctx ->
            task {
                let! body = JsonDocument.ParseAsync(ctx.Request.Body)
                let token =
                    body.RootElement.GetProperty("token").GetString()

                let! decoded =
                    FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token)

                let response =
                    {| uid = decoded.Uid |}

                ctx.Response.ContentType <- "application/json"
                do! ctx.Response.WriteAsync(
                    JsonSerializer.Serialize(response)
                )
            }
        )) |> ignore

        // ---- RUN ----
        app.Run()
        0
