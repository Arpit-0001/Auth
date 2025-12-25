open System
open System.IO
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.DependencyInjection
open FirebaseAdmin
open Google.Apis.Auth.OAuth2
open FirebaseAdmin.Auth

let initializeFirebase () =
    let json = Environment.GetEnvironmentVariable("FIREBASE_SERVICE_ACCOUNT")
    if String.IsNullOrEmpty(json) then
        failwith "FIREBASE_SERVICE_ACCOUNT environment variable is required."

    let credential = GoogleCredential.FromJson(json)
    let options = AppOptions(Credential = credential)
    if FirebaseApp.DefaultInstance = null then
        FirebaseApp.Create(options) |> ignore
    else
        printfn "FirebaseApp already initialized."

[<EntryPoint>]
let main args =
    initializeFirebase ()

    let builder = WebApplication.CreateBuilder(args)

    // Add services
    builder.Services.AddEndpointsApiExplorer() |> ignore
    builder.Services.AddSwaggerGen() |> ignore

    let app = builder.Build()

    // Swagger in development (optional, helpful for testing)
    if app.Environment.IsDevelopment() then
        app.UseSwagger() |> ignore
        app.UseSwaggerUI() |> ignore

    app.UseHttpsRedirection() |> ignore

    // POST /verify - Verify Firebase ID Token
    app.MapPost("/verify", Func<HttpContext, Task<IResult>>(fun context ->
        task {
            try
                use reader = new StreamReader(context.Request.Body)
                let! body = reader.ReadToEndAsync()

                if String.IsNullOrWhiteSpace(body) then
                    return Results.BadRequest({| error = "Request body is empty" |})

                let jsonDoc = JsonDocument.Parse(body)
                if not (jsonDoc.RootElement.TryGetProperty("idToken", &let prop) && prop.ValueKind = JsonValueKind.String then
                    return Results.BadRequest({| error = "idToken is required in JSON body" |})

                let idToken = jsonDoc.RootElement.GetProperty("idToken").GetString()

                let! decodedToken = FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(idToken)

                let response =
                    {|
                        uid = decodedToken.Uid
                        email = decodedToken.Claims.TryGetValue("email") |> function true, (:? string as e) -> e | _ -> null
                        email_verified = decodedToken.Claims.TryGetValue("email_verified") |> function true, (:? bool as v) -> v | _ -> false
                        verified = true
                    |}

                return Results.Ok(response)
            with
            | :? FirebaseAuthException as ex ->
                return Results.Unauthorized() |> fun r -> r.Value <- {| error = ex.Message; verified = false |}; r
            | ex ->
                return Results.StatusCode(500) |> fun r -> r.Value <- {| error = ex.Message |}; r
        }
    ))
    |> ignore

    app.Run()

    0
