namespace AuthServer

open System
open System.Text.Json
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting

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
// Firebase Init
// --------------------

module Firebase =

    let init () =
        if FirebaseApp.DefaultInstance = null then
            let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")

            if String.IsNullOrWhiteSpace(json) then
                failwith "FIREBASE_SERVICE_ACCOUNT not set"

            let credential = GoogleCredential.FromJson(json)

            let options = AppOptions()
            options.Credential <- credential

            FirebaseApp.Create(options) |> ignore

// --------------------
// Program
// --------------------

module Program =

    [<EntryPoint>]
    let main args =

        Firebase.init()

        let builder = WebApplication.CreateBuilder(args)
        let app = builder.Build()

        let projectId =
            FirebaseApp.DefaultInstance.Options.ProjectId

        let db = FirestoreDb.Create(projectId)

        let authHandler : RequestDelegate =
            RequestDelegate(fun ctx ->
                task {

                    let! body =
                        JsonSerializer.DeserializeAsync<AuthRequest>(ctx.Request.Body)

                    // ---- App config ----
                    let! appSnap =
                        db.Collection("app").Document("config").GetSnapshotAsync()

                    // ---- User ----
                    let! userSnap =
                        db.Collection("users").Document(body.accountId).GetSnapshotAsync()

                    if not userSnap.Exists then
                        ctx.Response.StatusCode <- 401
                        do! ctx.Response.WriteAsync("Unauthorized")
                    else
                        let appJson = appSnap.ToDictionary() |> JsonSerializer.Serialize
                        let userJson = userSnap.ToDictionary() |> JsonSerializer.Serialize

                        let response =
                            $"{{\"app\":{appJson},\"user\":{userJson}}}"

                        ctx.Response.ContentType <- "application/json"
                        do! ctx.Response.WriteAsync(response)
                }
            )

        app.MapPost("/auth", authHandler) |> ignore

        app.Run()
        0
