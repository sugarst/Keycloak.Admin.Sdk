using Keycloak.Admin.Sdk.Hosting;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class LogoutStorageTests
{
    [TestMethod]
    public async Task OutOfOrderLogoutDeliveryNeverShortensRevocationFreshnessOrRetention()
    {
        var now = DateTimeOffset.UtcNow; var clock = new Clock(now); var store = new InMemoryKeycloakLogoutStore(1, clock);
        await store.RevokeAsync("issuer", "newer", null, "user", now, now.AddHours(3), default);
        await store.RevokeAsync("issuer", "older", null, "user", now.AddMinutes(-1), now.AddHours(2), default);
        Assert.IsTrue(await store.IsRevokedAsync("issuer", "session", "user", now, default));
        await store.RevokeAsync("issuer", "newest", null, "user", now.AddMinutes(1), now.AddHours(4), default);
        Assert.IsTrue(await store.IsRevokedAsync("issuer", "session", "user", now.AddSeconds(30), default));
        clock.Now = now.AddHours(3.5);
        Assert.IsTrue(await store.IsRevokedAsync("issuer", "session", "user", now, default));
        clock.Now = now.AddHours(4);
        Assert.IsFalse(await store.IsRevokedAsync("issuer", "session", "user", now, default));
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    { internal DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }
}
