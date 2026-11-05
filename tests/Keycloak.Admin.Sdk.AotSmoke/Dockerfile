FROM mcr.microsoft.com/dotnet/sdk:10.0.403-alpine3.24 AS build
RUN apk add --no-cache clang build-base zlib-dev
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src ./src
COPY tests ./tests
COPY contracts/capabilities ./contracts/capabilities
RUN dotnet publish tests/Keycloak.Admin.Sdk.AotSmoke -c Release -r linux-musl-x64 -o /out
RUN /out/Keycloak.Admin.Sdk.AotSmoke
FROM scratch AS export
COPY --from=build /out/ /
FROM build AS integration-build
RUN dotnet publish tests/Keycloak.Admin.Sdk.IntegrationTests -c Release -r linux-musl-x64 -p:PublishAot=true -p:IlcTreatWarningsAsErrors=true -o /integration
FROM scratch AS integration-export
COPY --from=integration-build /integration/ /
