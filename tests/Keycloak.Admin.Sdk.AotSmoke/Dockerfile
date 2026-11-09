ARG SDK_IMAGE
FROM ${SDK_IMAGE} AS source
RUN apk add --no-cache clang build-base zlib-dev
WORKDIR /src
COPY global.json Directory.Build.props Target.props Keycloak.Admin.Sdk.slnx ./
COPY src ./src
COPY tests ./tests
COPY contracts ./contracts
COPY tools ./tools
COPY local/keycloak/*.cs local/keycloak/*.yaml ./local/keycloak/
COPY local/keycloak/kerberos ./local/keycloak/kerberos/
FROM source AS build
COPY --from=sdkpackages / /sdk-packages/
RUN dotnet publish tests/Keycloak.Admin.Sdk.AotSmoke -c Release -r linux-musl-x64 -p:SdkPackageFeed=/sdk-packages -p:TrimmerSingleWarn=false -o /out
RUN /out/Keycloak.Admin.Sdk.AotSmoke
FROM scratch AS export
COPY --from=build /out/ /
FROM source AS integration-build
RUN dotnet publish tests/Keycloak.Admin.Sdk.IntegrationTests -c Release -r linux-musl-x64 -p:PublishAot=true -p:IlcTreatWarningsAsErrors=true -o /integration
FROM scratch AS integration-export
COPY --from=integration-build /integration/ /
