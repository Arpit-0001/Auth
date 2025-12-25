namespace AuthServer

open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.Hosting

module Program =

    [<EntryPoint>]
    let main args =
        let builder = WebApplication.CreateBuilder(args)
        let app = builder.Build()

        app.MapGet("/", fun () -> "AuthServer running") |> ignore

        app.Run()
        0
