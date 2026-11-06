namespace Keycloak.Admin.Sdk.Protocols;

/// <summary>OAuth token response types supported by Keycloak 26.8.1. Refresh requires explicit client configuration and a live online user session.</summary>
public enum TokenExchangeRequestedTokenType { AccessToken, IdToken, RefreshToken, Saml2 }

/// <summary>External subject formats accepted by legacy provider exchange. Internal realm-to-realm exchange accepts access tokens only.</summary>
public enum TokenExchangeSubjectTokenType { AccessToken, IdToken, Jwt }
