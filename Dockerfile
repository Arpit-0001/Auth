# Build stage
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy project file and restore
COPY AuthServer/AuthServer.fsproj ./AuthServer/
RUN dotnet restore AuthServer/AuthServer.fsproj

# Copy everything else and publish
COPY . .
WORKDIR /src/AuthServer
RUN dotnet publish -c Release -o /app/out --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS runtime
WORKDIR /app
COPY --from=build /app/out ./

EXPOSE 80
ENV ASPNETCORE_URLS=http://+:80

ENTRYPOINT ["dotnet", "AuthServer.dll"]
