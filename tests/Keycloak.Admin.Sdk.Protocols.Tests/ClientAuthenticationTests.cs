using System.Security.Cryptography;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class ClientAuthenticationTests
{
    [TestMethod]
    public async Task SignedClientAssertionsUseFreshIdsExactAudienceBoundedLifetimeAndCancellation()
    {
        using var http = new HttpClient(); var oidc = new OidcClient(new(http, new("https://identity.invalid/"), "r")); using var key = RSA.Create(2048);
        var signing = new SigningCredentials(new RsaSecurityKey(key), "RS256"); var signer = new ClientAssertionSigner("client", oidc, signing, clock: TimeProvider.System);
        string first = await signer.CreateAsync(), second = await signer.CreateAsync(); var token = new JsonWebToken(first);
        Assert.AreNotEqual(new JsonWebToken(second).Id, token.Id); Assert.AreEqual("client", token.Issuer); Assert.AreEqual("client", token.Subject);
        Assert.AreEqual("https://identity.invalid/realms/r/protocol/openid-connect/token", token.Audiences.Single());
        Assert.IsTrue(token.ValidTo - token.IssuedAt <= TimeSpan.FromMinutes(1));
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(first, new TokenValidationParameters { ValidIssuer = "client", ValidAudience = token.Audiences.Single(), IssuerSigningKey = signing.Key, ValidAlgorithms = ["RS256"] });
        Assert.IsTrue(result.IsValid);
        var symmetric = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), "HS256");
        string secretJwt = await new ClientAssertionSigner("client", oidc, symmetric, TimeSpan.FromSeconds(30)).CreateAsync(); Assert.AreEqual("HS256", new JsonWebToken(secretJwt).Alg);
        Assert.Throws<ArgumentException>(() => new ClientAssertionSigner("", oidc, signing)); Assert.Throws<ArgumentNullException>(() => new ClientAssertionSigner("c", null!, signing));
        Assert.Throws<ArgumentNullException>(() => new ClientAssertionSigner("c", oidc, null!));
        Assert.Throws<ArgumentException>(() => new ClientAssertionSigner("c", oidc, new(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), "none")));
        foreach (TimeSpan lifetime in new[] { TimeSpan.Zero, TimeSpan.FromMinutes(6) }) Assert.Throws<ArgumentOutOfRangeException>(() => new ClientAssertionSigner("c", oidc, signing, lifetime));
        using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => signer.CreateAsync(cancel.Token).AsTask());
    }
    [TestMethod]
    public async Task ProjectedCredentialsFollowFileRotationAndRejectUnboundedMalformedOrCancelledReads()
    {
        string file = Path.Combine(Path.GetTempPath(), "keycloak-workload-" + Guid.NewGuid().ToString("N"));
        try
        {
            var projected = new ProjectedWorkloadToken(file); await File.WriteAllTextAsync(file, "first.jwt\n"); Assert.AreEqual("first.jwt", await projected.ReadAsync());
            await File.WriteAllTextAsync(file, "rotated.jwt"); Assert.AreEqual("rotated.jwt", await projected.ReadAsync());
            foreach (string invalid in new[] { "", "\n", "token with whitespace", new string('a', 65537) })
            { await File.WriteAllTextAsync(file, invalid); await Assert.ThrowsAsync<InvalidDataException>(() => projected.ReadAsync().AsTask()); }
            await File.WriteAllBytesAsync(file, [0xff, 0xfe]); await Assert.ThrowsAsync<System.Text.DecoderFallbackException>(() => projected.ReadAsync().AsTask());
            using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAsync<OperationCanceledException>(() => projected.ReadAsync(cancel.Token).AsTask());
            Assert.Throws<ArgumentException>(() => new ProjectedWorkloadToken("relative.jwt")); Assert.Throws<ArgumentException>(() => new ProjectedWorkloadToken(""));
        }
        finally { File.Delete(file); }
    }
}
