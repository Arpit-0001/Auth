namespace AuthServer

open System
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.Hosting

module Program =

    [<EntryPoint>]
    let main args =
        let builder = WebApplication.CreateBuilder(args)

        let app = builder.Build()

        app.MapGet("/", fun () ->
            Results.Ok("AuthServer is running")
        ) |> ignore

        app.Run()
        0
