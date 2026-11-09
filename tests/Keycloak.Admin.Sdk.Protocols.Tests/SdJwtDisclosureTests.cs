using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class SdJwtDisclosureTests
{
    [TestMethod]
    public void RecursiveObjectAndArrayDisclosuresPreserveOnlyAuthenticatedValues()
    {
        foreach (string algorithm in new[] { "sha-256", "sha-384", "sha-512" })
        {
            string child = Disclosure("[\"salt\",\"locality\",\"London\"]");
            string parent = Disclosure(new JsonArray(JsonValue.Create("salt"), JsonValue.Create("address"), new JsonObject { ["_sd"] = new JsonArray(JsonValue.Create(Hash(algorithm, child))) }).ToJsonString());
            string item = Disclosure("[\"salt\",{\"name\":\"Alice\"}]");
            var claims = new JsonObject { ["_sd_alg"] = algorithm, ["_sd"] = new JsonArray(JsonValue.Create(Hash(algorithm, parent))),
                ["array"] = new JsonArray(new JsonObject { ["..."] = Hash(algorithm, item) }, new JsonObject { ["..."] = "decoy-array" }, JsonValue.Create(true), null),
                ["plain"] = new JsonObject { ["number"] = 12.5 } };
            var result = SdJwtDisclosures.Resolve(Json(claims.ToJsonString()), [parent, child, item]);
            Assert.AreEqual("London", result.GetProperty("address").GetProperty("locality").GetString());
            Assert.AreEqual("Alice", result.GetProperty("array")[0].GetProperty("name").GetString()); Assert.AreEqual(3, result.GetProperty("array").GetArrayLength());
            Assert.IsFalse(result.TryGetProperty("_sd_alg", out _)); Assert.AreEqual(12.5, result.GetProperty("plain").GetProperty("number").GetDouble());
            Assert.AreEqual(0, SdJwtDisclosures.Resolve(Json(claims.ToJsonString()), []).GetProperty("array").GetArrayLength() - 2);
        }
        string ordinary = Disclosure("[\"salt\",\"claim\",null]");
        var defaultHash = Json("{\"_sd\":[\"" + Hash("sha-256", ordinary) + "\",\"decoy-object\"]}");
        Assert.AreEqual(JsonValueKind.Null, SdJwtDisclosures.Resolve(defaultHash, [ordinary]).GetProperty("claim").ValueKind);
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(defaultHash, Enumerable.Repeat(ordinary, 101).ToArray()));
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{\"_sd_alg\":\"sha-1\"}"), []));
    }

    [TestMethod]
    public void MalformedUnboundDuplicateAndOverwritingDisclosuresAreRejected()
    {
        foreach (string text in new[] { "{}", "[]", "[\"salt\"]", "[\"salt\",1,2,3]", "[1,\"name\",\"value\"]", "[\"\",\"name\",\"value\"]" })
            Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{}"), [Disclosure(text)]));
        foreach (string value in new[] { "", "not*base64", new string('a', 65537) }) Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{}"), [value]));
        foreach (string value in new[] { "aa-a", "aa_a" }) Assert.Throws<JsonException>(() => SdJwtDisclosures.Resolve(Json("{}"), [value]));
        string proof = Disclosure("[\"salt\",\"name\",\"value\"]"), hash = Hash("sha-256", proof);
        string arrayProof = Disclosure("[\"salt\",\"array-value\"]"), arrayHash = Hash("sha-256", arrayProof);
        var root = Json("{\"_sd\":[\"" + hash + "\"]}");
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(root, [proof, proof]));
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{}"), [proof]));
        foreach (string bad in new[] { "{\"_sd\":{}}", "{\"_sd\":[1]}", "{\"_sd\":[\"\"]}", "{\"...\":\"digest\"}",
            "{\"nested\":{\"_sd_alg\":\"sha-256\"}}", "{\"_sd\":[\"" + hash + "\",\"" + hash + "\"]}", "{\"name\":\"signed\",\"_sd\":[\"" + hash + "\"]}",
            "{\"_sd\":[\"" + arrayHash + "\"]}", "{\"array\":[{\"...\":\"" + hash + "\"}]}", "{\"array\":[{\"...\":null}]}",
            "{\"array\":[{\"...\":\"\"}]}", "{\"array\":[{\"...\":\"" + hash + "\",\"extra\":1}]}", "{\"a\":1,\"a\":2}" })
            Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json(bad), [proof, arrayProof]));
        foreach (string name in new[] { "_sd", "_sd_alg", "..." })
        {
            string encoded = Disclosure(new JsonArray(JsonValue.Create("salt"), JsonValue.Create(name), JsonValue.Create("value")).ToJsonString());
            Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{\"_sd\":[\"" + Hash("sha-256", encoded) + "\"]}"), [encoded]));
        }
        string invalidName = Disclosure("[\"salt\",1,\"value\"]");
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{\"_sd\":[\"" + Hash("sha-256", invalidName) + "\"]}"), [invalidName]));
        string deep = new string('[', 33) + "null" + new string(']', 33);
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(Json("{\"nested\":" + deep + "}"), []));
        var excessive = Json("{\"_sd\":[" + string.Join(',', Enumerable.Range(0, 1001).Select(i => "\"digest-" + i + "\"")) + "]}");
        Assert.Throws<InvalidDataException>(() => SdJwtDisclosures.Resolve(excessive, []));
    }
    private static string Disclosure(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
    private static string Hash(string algorithm, string value) => SdJwtDisclosures.Hash(algorithm, value);
    private static JsonElement Json(string text) { using var document = JsonDocument.Parse(text); return document.RootElement.Clone(); }
}
