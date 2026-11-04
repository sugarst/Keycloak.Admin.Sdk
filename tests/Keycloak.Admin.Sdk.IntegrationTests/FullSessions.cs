using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static LiveContext;

internal static class FullSessions
{
    public static async Task RunAsync(LiveContext c, LiveFacts f, HttpClient http, Uri server)
    {
        var up = new[] { ("user-id", f.User) }; var cp = new[] { ("client-uuid", f.Client) };
        var config = O("""{"eventsEnabled":true,"eventsExpiration":3600,"enabledEventTypes":["LOGIN","LOGIN_ERROR","LOGOUT"],"eventsListeners":["jboss-logging"],"adminEventsEnabled":true,"adminEventsDetailsEnabled":true}""");
        var setEvents = await c.Put("events/config", config);
        var getEvents = await c.Get("events/config");
        c.Prove(getEvents.J?["eventsExpiration"]?.GetValue<int>() == 3600 && getEvents.J?["enabledEventTypes"]?.AsArray().Any(n => n?.GetValue<string>() == "LOGIN") == true, "Event configuration persists retention and enabled event types", setEvents, getEvents);
        var token = await FullCredentials.PasswordToken(http, server, c.Realm, f.Password, "openid offline_access");
        c.Prove(S(token, "refresh_token").Length > 100, "Actual OIDC offline grant returns refresh token");
        var sessions = await c.Get("users/{user-id}/sessions", null, up);
        var clientSessions = await c.Get("clients/{client-uuid}/user-sessions", null, cp);
        var count = await c.Get("clients/{client-uuid}/session-count", null, cp);
        var stats = await c.Get("client-session-stats");
        string sid = S(sessions.J!.AsArray().Last(), "id");
        c.Prove(sid.Length > 0 && Has(clientSessions.J, "id", sid) && count.J?["count"]?.GetValue<int>() > 0 && Has(stats.J, "clientId", "full-client"), "Real password grant creates persisted user/client session and counted client statistics", sessions, clientSessions, count, stats);
        var offline = await c.Get("users/{user-id}/offline-sessions/{clientUuid}", null, [.. up, ("clientUuid", f.Client)]);
        var co = await c.Get("clients/{client-uuid}/offline-sessions", null, cp);
        var oc = await c.Get("clients/{client-uuid}/offline-session-count", null, cp);
        c.Prove(offline.J is JsonArray { Count: > 0 } && co.J is JsonArray { Count: > 0 } && oc.J?["count"]?.GetValue<int>() > 0 && Has(co.J, "userId", f.User), "Offline grant persists user/client offline session and count", offline, co, oc);
        var ui = await c.Get("ui-ext/sessions", O("""{"search":"full-user","type":"REGULAR","max":100}"""));
        var uic = await c.Get("ui-ext/sessions/client", new JsonObject { ["clientId"] = f.Client, ["type"] = "OFFLINE", ["max"] = 100 });
        c.Prove(Has(ui.J, "userId", f.User) && Has(uic.J, "userId", f.User) && Has(uic.J, "type", "OFFLINE"), "UI session projections filter real regular/offline sessions", ui, uic);
        var deleted = await c.Delete("sessions/{session}", ("session", sid));
        sessions = await c.Get("users/{user-id}/sessions", null, up);
        c.Prove(!Has(sessions.J, "id", sid), "Deleting session removes selected persisted user session", deleted, sessions);
        await FullCredentials.PasswordToken(http, server, c.Realm, f.Password);
        var logout = await c.Post("users/{user-id}/logout", paths: up);
        sessions = await c.Get("users/{user-id}/sessions", null, up);
        c.Prove(sessions.J is JsonArray { Count: 0 }, "User logout invalidates all regular sessions for that user", logout, sessions);
        var impersonate = await c.Post("users/{user-id}/impersonation", paths: up);
        sessions = await c.Get("users/{user-id}/sessions", null, up);
        c.Prove(S(impersonate.J, "redirect").Contains(c.Realm, StringComparison.Ordinal) && sessions.J is JsonArray { Count: > 0 }, "Impersonation creates actual target-user session and realm redirect", impersonate, sessions);
        var all = await c.Post("logout-all"); sessions = await c.Get("users/{user-id}/sessions", null, up);
        c.Prove(sessions.J is JsonArray { Count: 0 }, "Realm logout-all removes existing user sessions", all, sessions);
        await Consent(c, f, server);
        await c.Put("", O("""{"bruteForceProtected":true,"failureFactor":2,"waitIncrementSeconds":60,"maxFailureWaitSeconds":60,"quickLoginCheckMilliSeconds":1000,"minimumQuickLoginWaitSeconds":60}"""));
        async Task FailLogin()
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "full-client", ["client_secret"] = "full-client-secret", ["username"] = "full-user", ["password"] = "deliberately-incorrect-password" });
            using var response = await http.PostAsync(new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/token"), form);
            c.Prove(response.StatusCode == HttpStatusCode.BadRequest, "Actual incorrect-password login is rejected");
        }
        await FailLogin(); await FailLogin();
        LiveReply status = await c.Get("attack-detection/brute-force/users/{userId}", null, ("userId", f.User));
        for (int i = 0; i < 30 && (status.J?["numFailures"]?.GetValue<int>() ?? 0) == 0; i++) { await Task.Delay(100); status = await c.Get("attack-detection/brute-force/users/{userId}", null, ("userId", f.User)); }
        c.Prove(status.J?["numFailures"]?.GetValue<int>() > 0, "Failed real logins produce persisted brute-force failure count", status);
        var bruteUi = await c.Get("ui-ext/brute-force-user", O("""{"username":"full-user","exact":true}"""));
        c.Prove(Has(bruteUi.J, "id", f.User), "UI brute-force search resolves actual failed-login user", bruteUi);
        var clear = await c.Delete("attack-detection/brute-force/users/{userId}", ("userId", f.User));
        status = await c.Get("attack-detection/brute-force/users/{userId}", null, ("userId", f.User));
        c.Prove(status.J?["numFailures"]?.GetValue<int>() == 0, "Clearing selected user's attacks resets recorded failures", clear, status);
        await FailLogin(); await Task.Delay(200);
        clear = await c.Delete("attack-detection/brute-force/users"); status = await c.Get("attack-detection/brute-force/users/{userId}", null, ("userId", f.User));
        c.Prove(status.J?["numFailures"]?.GetValue<int>() == 0, "Clearing realm attacks resets newly recorded failures", clear, status);
        var events = await c.Get("events", new JsonObject { ["user"] = f.User, ["max"] = 100 });
        c.Prove(Has(events.J, "type", "LOGIN") && Has(events.J, "type", "LOGIN_ERROR"), "Event queries return real successful and failed login events", events);
        var admin = await c.Get("admin-events", O("""{"max":100}"""));
        c.Prove(admin.J is JsonArray { Count: > 0 } && admin.J.AsArray().Any(n => S(n, "resourcePath").Contains(f.User, StringComparison.Ordinal)), "Admin events contain actual user mutation resource paths", admin);
        clear = await c.Delete("events"); events = await c.Get("events");
        c.Prove(events.J is JsonArray { Count: 0 }, "Deleting events removes persisted login history", clear, events);
        clear = await c.Delete("admin-events"); admin = await c.Get("admin-events");
        c.Prove(admin.J is JsonArray { Count: 0 } || admin.J!.AsArray().All(n => S(n, "operationType") == "DELETE" && S(n, "resourcePath") == "admin-events"), "Deleting admin events removes preceding mutation history", clear, admin);
        Console.WriteLine("PASS full sessions/events: actual grants, offline/regular state, consent, impersonation, logout, attacks and event history.");
    }
    private static async Task Consent(LiveContext c, LiveFacts f, Uri server)
    {
        await c.Put("clients/{client-uuid}", O("""{"consentRequired":true,"authorizationServicesEnabled":true}"""), ("client-uuid", f.Client));
        using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) { BaseAddress = server };
        var cookies = new Dictionary<string, string>(StringComparer.Ordinal);
        void ReceiveCookies(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (string value in values)
            {
                string pair = value.Split(';', 2)[0]; int separator = pair.IndexOf('=');
                if (separator > 0) cookies[pair[..separator]] = pair[(separator + 1)..];
            }
            browser.DefaultRequestHeaders.Remove("Cookie");
            if (cookies.Count > 0) browser.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", string.Join("; ", cookies.Select(p => p.Key + "=" + p.Value)));
        }
        string auth = new Uri(server, "realms/" + c.Realm + "/protocol/openid-connect/auth?client_id=full-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid%20profile%20email&state=full-consent").AbsoluteUri;
        using var page = await browser.GetAsync(auth);
        ReceiveCookies(page);
        string html = await page.Content.ReadAsStringAsync();
        c.Prove(cookies.ContainsKey("AUTH_SESSION_ID"), "Actual login response establishes authentication-session cookie");
        static string Action(string pageText) => WebUtility.HtmlDecode(Regex.Match(pageText, "<form[^>]*action=\"([^\"]+)\"", RegexOptions.IgnoreCase).Groups[1].Value);
        string action = Action(html);
        if (action.Length == 0) throw new InvalidOperationException("OIDC login form missing: " + html[..Math.Min(html.Length, 300)]);
        using var credentials = new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "full-user", ["password"] = f.Password, ["credentialId"] = "" });
        using var login = await browser.PostAsync(action, credentials);
        ReceiveCookies(login);
        html = await login.Content.ReadAsStringAsync();
        var location = login.Headers.Location;
        for (int redirects = 0; location is not null && redirects < 8; redirects++)
        {
            var target = location.IsAbsoluteUri ? location : new Uri(server, location);
            if (target.GetLeftPart(UriPartial.Authority) != server.GetLeftPart(UriPartial.Authority)) throw new InvalidOperationException("Consent must be shown before external authorization redirect.");
            using var next = await browser.GetAsync(target); ReceiveCookies(next);
            html = await next.Content.ReadAsStringAsync(); location = next.Headers.Location;
        }
        action = Action(html);
        if (html.Contains("name=\"password\"", StringComparison.Ordinal) && !html.Contains("consent", StringComparison.OrdinalIgnoreCase))
        {
            using var secondForm = new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "full-user", ["password"] = f.Password, ["credentialId"] = "" });
            using var secondLogin = await browser.PostAsync(action, secondForm);
            ReceiveCookies(secondLogin);
            html = await secondLogin.Content.ReadAsStringAsync(); action = Action(html);
        }
        if (action.Length == 0 || !html.Contains("consent", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("OIDC consent page missing after real login: " + html[..Math.Min(html.Length, 300)]);
        using var accept = new FormUrlEncodedContent(new Dictionary<string, string> { ["accept"] = "Yes" });
        using var consent = await browser.PostAsync(action, accept);
        c.Prove(consent.StatusCode == HttpStatusCode.Found && consent.Headers.Location?.OriginalString.Contains("code=", StringComparison.Ordinal) == true, "Actual browser login and consent issue authorization code");
        var grants = await c.Get("users/{user-id}/consents", null, ("user-id", f.User));
        c.Prove(grants.J is JsonArray { Count: > 0 } && grants.J.AsArray().Any(n => S(n?["client"], "clientId") == "full-client" || S(n, "clientId") == "full-client"), "Consent API reads persisted browser-approved client grant", grants);
        var revoke = await c.Delete("users/{user-id}/consents/{client}", ("user-id", f.User), ("client", "full-client"));
        grants = await c.Get("users/{user-id}/consents", null, ("user-id", f.User));
        c.Prove(grants.J is JsonArray { Count: 0 }, "Consent revocation removes persisted client grant", revoke, grants);
        await c.Put("clients/{client-uuid}", O("""{"consentRequired":false,"authorizationServicesEnabled":true}"""), ("client-uuid", f.Client));
    }
}
