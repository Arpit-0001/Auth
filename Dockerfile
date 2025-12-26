# ================= BUILD STAGE =================
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy csproj and restore
COPY AuthServer/AuthServer.csproj AuthServer/
RUN dotnet restore AuthServer/AuthServer.csproj

# Copy remaining files
COPY . .

# Publish
WORKDIR /src/AuthServer
RUN dotnet publish AuthServer.csproj -c Release -o /app/out

# ================= RUNTIME STAGE =================
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS runtime
WORKDIR /app

COPY --from=build /app/out .

EXPOSE 80
ENV ASPNETCORE_URLS=http://+:80

# OPTIONAL (but recommended)
ENV FIREBASE_DB_URL=""
ENV AUTH_SECRET="HMX_BY_MR_ARPIT_120"

ENTRYPOINT ["dotnet", "AuthServer.dll"]
