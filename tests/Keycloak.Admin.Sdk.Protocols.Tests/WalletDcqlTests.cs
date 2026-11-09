using System.Text.Json;
using System.Text.Json.Nodes;
using Keycloak.Admin.Sdk.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public sealed class WalletDcqlTests
{
    [TestMethod]
    public void DisclosuresMustSatisfyBoundedTypePathsValuesAndAlternativeClaimSets()
    {
        var claims = Json("""{"vct":"person","name":"Alice","addresses":[{"country":"DE"},2],"age":21}""");
        var query = Query();
        void Require() => Oid4vpDcql.Require(Json(query.ToJsonString()), "identity", claims);
        var requested = query["credentials"]![0]!;
        Require();
        requested["multiple"] = false; requested["require_cryptographic_holder_binding"] = true;
        requested["claims"] = JsonNode.Parse("""[{"id":"name","path":["name"],"values":["Alice"]},{"id":"country","path":["addresses",null,"country"],"values":["DE"]},{"id":"indexed","path":["addresses",1],"values":[2]}]""");
        Require();
        requested["claims"]![2]!["path"]![1] = 9;
        Assert.Throws<InvalidDataException>(Require);
        requested["claim_sets"] = JsonNode.Parse("""[["indexed"],["name","country"]]"""); Require();
        requested["claim_sets"] = JsonNode.Parse("""[[],[1],["unknown"]]"""); Assert.Throws<InvalidDataException>(Require);
        foreach (string bad in new[] { "null", "[]", "[[]]", "[null]", "[1]", "[\"unknown\"]" })
        { requested["claim_sets"] = JsonNode.Parse(bad); Assert.Throws<InvalidDataException>(Require); }
        requested.AsObject().Remove("claim_sets");
        foreach (string bad in new[] { "null", "[{\"path\":[]}]", "[{\"path\":false}]", "[{\"path\":[-1]}]", "[{\"path\":[1.5]}]", "[{\"path\":[true]}]", "[{\"path\":[\"name\"],\"unknown\":true}]",
            "[{\"id\":\"x\",\"path\":[\"name\"]},{\"id\":\"x\",\"path\":[\"age\"]}]", "[{\"path\":[\"name\"],\"values\":null}]", "[{\"path\":[\"name\"],\"values\":[]}]", "[{\"path\":[\"name\"],\"values\":[\"Bob\"]}]", "[{\"path\":[\"age\",0]}]", "[{\"path\":[\"age\",null]}]", "[{\"path\":[\"age\",\"name\"]}]" })
        { requested["claims"] = JsonNode.Parse(bad); Assert.Throws<InvalidDataException>(Require); }
        requested["claims"] = new JsonArray(Enumerable.Range(0, 101).Select(_ => (JsonNode)new JsonObject()).ToArray()); Assert.Throws<InvalidDataException>(Require);
        requested["claims"] = new JsonArray(new JsonObject { ["path"] = new JsonArray(Enumerable.Range(0, 33).Select(_ => (JsonNode)JsonValue.Create("a")!).ToArray()) }); Assert.Throws<InvalidDataException>(Require);
        requested["claims"] = new JsonArray(new JsonObject { ["path"] = new JsonArray("name"), ["values"] = new JsonArray(Enumerable.Range(0, 101).Select(_ => (JsonNode)JsonValue.Create("a")!).ToArray()) }); Assert.Throws<InvalidDataException>(Require);
        requested["claims"] = new JsonArray(); requested["claim_sets"] = new JsonArray(Enumerable.Range(0, 101).Select(_ => (JsonNode)new JsonArray()).ToArray()); Assert.Throws<InvalidDataException>(Require);
        foreach (Action<JsonNode> corrupt in new Action<JsonNode>[] { r => r["id"] = "foreign", r => r["format"] = "jwt_vc_json", r => r["unknown"] = true, r => r["multiple"] = true, r => r["require_cryptographic_holder_binding"] = false,
            r => r["meta"]!["vct_values"] = new JsonArray("other"), r => r["meta"]!["vct_values"] = false, r => r["meta"]!["vct_values"] = new JsonArray(1, "other") })
        { var fresh = Query(); corrupt(fresh["credentials"]![0]!); Assert.Throws<InvalidDataException>(() => Oid4vpDcql.Require(Json(fresh.ToJsonString()), "identity", claims)); }
        foreach (string bad in new[] { "{\"credentials\":null}", "{\"credentials\":[]}", "{\"credentials\":[{},{}]}", "{\"credentials\":[{}],\"other\":true}" })
            Assert.Throws<InvalidDataException>(() => Oid4vpDcql.Require(Json(bad), "identity", claims));
    }
    private static JsonObject Query() => JsonNode.Parse("""{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["person"]}}]}""")!.AsObject();
    private static JsonElement Json(string text) { using var d = JsonDocument.Parse(text); return d.RootElement.Clone(); }
}
