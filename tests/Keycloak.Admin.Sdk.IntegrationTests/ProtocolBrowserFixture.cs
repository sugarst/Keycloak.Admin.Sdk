using System.Net;
using System.Text.RegularExpressions;

// Test-only browser form driver for the pinned Keycloak login theme. Never use it to collect passwords in an application.
internal static partial class ProtocolBrowserFixture
{
    internal static async Task<(Uri Callback, bool Consented)> LoginAsync(Uri authorization, Uri callback, string username, string password, CancellationToken ct, HttpClient? sharedBrowser = null)
    {
        var result = await LoginCoreAsync(authorization, callback, username, password, false, ct, sharedBrowser: sharedBrowser);
        return (result.Callback, result.Consented);
    }
    internal static async Task<IReadOnlyDictionary<string, string>> LoginPostAsync(Uri authorization, Uri callback, string username, string password, CancellationToken ct)
        => (await LoginCoreAsync(authorization, callback, username, password, true, ct)).Form ?? throw new InvalidDataException("Expected an actual browser POST response.");
    internal static async Task<(Uri Callback, IReadOnlyDictionary<string, string>? Form)> LoginFromPostAsync(Uri destination, Uri callback,
        IEnumerable<KeyValuePair<string, string>> fields, string username, string password, bool expectPostResponse, CancellationToken ct)
    {
        var result = await LoginCoreAsync(destination, callback, username, password, expectPostResponse, ct, initialFields: fields);
        return (result.Callback, result.Form);
    }
    internal static async Task<Uri> DenyConsentAsync(Uri authorization, Uri callback, string username, string password, CancellationToken ct, HttpClient? sharedBrowser = null)
        => (await LoginCoreAsync(authorization, callback, username, password, false, ct, false, sharedBrowser)).Callback;
    internal static async Task<(Uri Callback, IReadOnlyDictionary<string, string>? Form, int PasswordChallenges, int OtpChallenges)> LoginWithOtpAsync(Uri authorization, Uri callback,
        string username, string password, Func<CancellationToken, ValueTask<string>> otp, bool postResponse, HttpClient browser, CancellationToken ct)
    {
        var result = await LoginCoreAsync(authorization, callback, username, password, postResponse, ct, sharedBrowser: browser, otp: otp);
        return (result.Callback, result.Form, result.PasswordChallenges, result.OtpChallenges);
    }
    internal static async Task<Uri> LoginWithAuthenticatorAsync(Uri authorization, Uri callback, string username, string password,
        Func<string, Dictionary<string, string>?> challenge, CancellationToken ct, HttpClient? browser = null)
        => (await LoginCoreAsync(authorization, callback, username, password, false, ct, sharedBrowser: browser, challenge: challenge)).Callback;
    private sealed record BrowserResult(Uri Callback, bool Consented, IReadOnlyDictionary<string, string>? Form = null, int PasswordChallenges = 0, int OtpChallenges = 0);
    private static async Task<BrowserResult> LoginCoreAsync(Uri authorization, Uri callback, string username, string password, bool capturePost, CancellationToken ct, bool approveConsent = true, HttpClient? sharedBrowser = null,
        IEnumerable<KeyValuePair<string, string>>? initialFields = null, Func<CancellationToken, ValueTask<string>>? otp = null, Func<string, Dictionary<string, string>?>? challenge = null)
    {
        using var handler = sharedBrowser is null ? new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true } : null;
        using var ownedBrowser = handler is null ? null : new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        var browser = sharedBrowser ?? ownedBrowser!;
        // .NET CookieContainer does not implement browsers' Secure-cookie loopback exception.
        // Exercise Keycloak's explicit Safari HTTP-loopback compatibility branch in this isolated fixture.
        browser.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15");
        Uri current = authorization; bool usernameSent = false, passwordSent = false, consented = false; int otpChallenges = 0;
        HttpContent? body = initialFields is null ? null : new FormUrlEncodedContent(initialFields);
        for (int step = 0; step < 12; step++)
        {
            if (current.GetLeftPart(UriPartial.Path) == callback.AbsoluteUri) return new(current, consented, PasswordChallenges: passwordSent ? 1 : 0, OtpChallenges: otpChallenges);
            if (current.GetLeftPart(UriPartial.Authority) != authorization.GetLeftPart(UriPartial.Authority)) throw new InvalidDataException("Test login attempted an external redirect.");
            using var request = new HttpRequestMessage(body is null ? HttpMethod.Get : HttpMethod.Post, current) { Content = body };
            using var response = await browser.SendAsync(request, ct); body = null;
            Console.WriteLine($"Browser fixture: {step} {request.Method} {current.AbsolutePath} {(int)response.StatusCode} {response.Content.Headers.ContentType?.MediaType}");
            if ((int)response.StatusCode is >= 300 and < 400)
            {
                current = new Uri(current, response.Headers.Location ?? throw new InvalidDataException("Missing browser redirect.")); continue;
            }
            string html = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                string[] known = ["HTTPS required", "Invalid parameter: redirect_uri", "Invalid Request", "Cookie not found", "Invalid username or password", "Invalid parameter: code_challenge_method", "Client not found", "Unexpected error"];
                var message = Regex.Match(html, "<span[^>]*class=\"kc-feedback-text\"[^>]*>([^<]{0,200})</span>", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                throw new InvalidDataException($"Pinned browser fixture failed at step {step} ({(int)response.StatusCode}): " + string.Join(", ", known.Where(html.Contains)) + (message.Success ? WebUtility.HtmlDecode(message.Groups[1].Value) : ""));
            }
            var challengeFields = challenge?.Invoke(html);
            var matchingForms = Forms().Matches(html).Cast<Match>().Where(m => (challengeFields is null && m.Value.Contains("id=\"kc-form-login\"", StringComparison.Ordinal))
                || (challengeFields is not null && (m.Value.Contains("id=\"register\"", StringComparison.Ordinal) || m.Value.Contains("id=\"webauth\"", StringComparison.Ordinal)
                    || m.Value.Contains("id=\"kc-recovery-codes-settings-form\"", StringComparison.Ordinal) || m.Value.Contains("id=\"kc-recovery-code-login-form\"", StringComparison.Ordinal)
                    || m.Value.Contains("id=\"kc-update-email-form\"", StringComparison.Ordinal) || m.Value.Contains("id=\"kc-update-profile-form\"", StringComparison.Ordinal) || m.Value.Contains("id=\"kc-passwd-update-form\"", StringComparison.Ordinal)))
                || (m.Value.Contains("name=\"accept\"", StringComparison.Ordinal) && m.Value.Contains("name=\"cancel\"", StringComparison.Ordinal))
                || (challengeFields is null && m.Value.Contains("id=\"kc-continue\"", StringComparison.Ordinal) && m.Value.Contains("name=\"cancel-aia\"", StringComparison.Ordinal))
                || (otp is not null && m.Value.Contains("id=\"kc-otp-login-form\"", StringComparison.Ordinal))
                || (capturePost && (new[] { "SAMLResponse", "response", "code", "id_token", "access_token" }.Any(name => m.Value.Contains("name=\"" + name + "\"", StringComparison.OrdinalIgnoreCase))
                    || WebUtility.HtmlDecode(Attribute(m.Value, "action", false)) == callback.AbsoluteUri))).ToArray();
            if (matchingForms.Length != 1) throw new InvalidDataException("Expected one pinned login, challenge or response form; matching ids: " + string.Join(',', matchingForms.Select(f => Attribute(f.Value[..(f.Value.IndexOf('>') + 1)], "id", false))));
            Match form = matchingForms[0];
            string action = Attribute(form.Value, "action"); current = new Uri(current, WebUtility.HtmlDecode(action));
            var fields = new Dictionary<string, string>();
            foreach (Match input in Inputs().Matches(form.Value))
            {
                string name = Attribute(input.Value, "name", false);
                if (name.Length != 0 && Attribute(input.Value, "type", false).Equals("hidden", StringComparison.OrdinalIgnoreCase)) fields[name] = WebUtility.HtmlDecode(Attribute(input.Value, "value", false));
            }
            if (capturePost && (current == callback || new[] { "SAMLResponse", "response", "code", "id_token", "access_token" }.Any(fields.ContainsKey)))
            {
                if (current != callback) throw new InvalidDataException("Protocol test form targeted an unexpected callback.");
                return new(current, consented, fields, passwordSent ? 1 : 0, otpChallenges);
            }
            if (challengeFields is not null && !form.Value.Contains("id=\"kc-form-login\"", StringComparison.Ordinal))
            { foreach (var field in challengeFields) fields[field.Key] = field.Value; }
            else if (form.Value.Contains("id=\"kc-form-login\"", StringComparison.Ordinal))
            {
                var names = Inputs().Matches(form.Value).Cast<Match>().Select(input => Attribute(input.Value, "name", false)).ToHashSet(StringComparer.Ordinal);
                bool asksUsername = names.Contains("username"), asksPassword = names.Contains("password");
                if ((asksPassword && passwordSent) || (asksUsername && usernameSent && !asksPassword) || (!asksUsername && !asksPassword))
                {
                    string[] failures = ["Invalid username or password", "Invalid password", "Invalid username", "Account is disabled", "Account is not fully set up", "Account temporarily disabled"];
                    throw new InvalidDataException("Test login credential step was refused: " + string.Join(',', failures.Where(html.Contains)));
                }
                if (asksUsername) { usernameSent = true; fields["username"] = username; }
                if (asksPassword) { passwordSent = true; fields["password"] = password; fields["credentialId"] = ""; }
            }
            else if (form.Value.Contains("id=\"kc-otp-login-form\"", StringComparison.Ordinal))
            {
                if (otp is null || ++otpChallenges > 1) throw new InvalidDataException("Test second-factor authentication was refused.");
                fields["otp"] = await otp(ct);
            }
            else if (form.Value.Contains("name=\"cancel-aia\"", StringComparison.Ordinal))
            { consented = true; fields[approveConsent ? "continue" : "cancel-aia"] = approveConsent ? "Continue" : "Cancel"; }
            else { consented = true; fields[approveConsent ? "accept" : "cancel"] = approveConsent ? "Yes" : "No"; }
            body = new FormUrlEncodedContent(fields);
        }
        body?.Dispose(); throw new InvalidDataException("Test login exceeded bounded redirect count.");
    }

    private static string Attribute(string html, string name, bool required = true)
    {
        var match = Regex.Match(html, "\\b" + name + "=[\"']([^\"']*)[\"']", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        if (!match.Success && required) throw new InvalidDataException("Pinned form attribute missing.");
        return match.Success ? match.Groups[1].Value : "";
    }
    [GeneratedRegex("<form\\b[^>]*>.*?</form>", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)] private static partial Regex Forms();
    [GeneratedRegex("<input\\b[^>]*>", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)] private static partial Regex Inputs();
}
