namespace Keycloak.Admin.Sdk.Protocols;

public enum OidcAuthorizationResponseMode { Query, Fragment, FormPost, QueryJwt, FragmentJwt, FormPostJwt, Jwt }

internal static class OidcResponseModes
{
    internal static bool Signed(this OidcAuthorizationResponseMode mode) => mode is OidcAuthorizationResponseMode.QueryJwt or OidcAuthorizationResponseMode.FragmentJwt or OidcAuthorizationResponseMode.FormPostJwt or OidcAuthorizationResponseMode.Jwt;
    internal static bool Post(this OidcAuthorizationResponseMode mode) => mode is OidcAuthorizationResponseMode.FormPost or OidcAuthorizationResponseMode.FormPostJwt;
    internal static bool Fragment(this OidcAuthorizationResponseMode mode) => mode is OidcAuthorizationResponseMode.Fragment or OidcAuthorizationResponseMode.FragmentJwt;
    internal static string Wire(this OidcAuthorizationResponseMode mode) => mode switch
    {
        OidcAuthorizationResponseMode.Query => "query", OidcAuthorizationResponseMode.Fragment => "fragment", OidcAuthorizationResponseMode.FormPost => "form_post",
        OidcAuthorizationResponseMode.QueryJwt => "query.jwt", OidcAuthorizationResponseMode.FragmentJwt => "fragment.jwt", OidcAuthorizationResponseMode.FormPostJwt => "form_post.jwt",
        OidcAuthorizationResponseMode.Jwt => "jwt", _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };
}
