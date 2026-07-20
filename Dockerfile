# syntax=docker/dockerfile:1

# Build stage: restore against the committed lock files, then publish.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# .editorconfig carries the analyzer severities (the build treats warnings as
# errors), so it must be present or a clean container build diverges from local.
COPY global.json Directory.Build.props Directory.Packages.props .editorconfig ./
COPY src/ src/
RUN dotnet restore src/Starter.App/Starter.App.csproj
RUN dotnet publish src/Starter.App/Starter.App.csproj -c Release -o /app --no-restore

# Runtime stage: the ASP.NET Core runtime image, running as its built-in
# non-root user. The image defaults the listen port to 8080.
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Starter.App.dll"]
