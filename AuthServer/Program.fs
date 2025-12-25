namespace AuthServer

open System
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.DependencyInjection
open System.Text.Json

module Program =

    [<EntryPoint>]
    let main args =

        let builder = WebApplication.CreateBuilder(args)

        // Add routing
        builder.Services.AddRouting() |> ignore

        let app = builder.Build()

        // Default GET to confirm running
        app.MapGet("/", Func<string>(fun () ->
            "🚀 AuthServer is running"
        )) |> ignore

        // Simple POST auth test
        app.MapPost("/auth", Func<HttpContext, Task>(fun ctx ->
            task {
                // Read request body as JSON if present
                let! reqObj = JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body)

                // Build example response
                let response = 
                    {| 
                        message = "Auth endpoint reached"
                        received = reqObj 
                    |}

                ctx.Response.ContentType <- "application/json"
                do! JsonSerializer.SerializeAsync(ctx.Response.Body, response)
            }
        )) |> ignore

        // Run HTTP server forever
        app.Run()
        0
