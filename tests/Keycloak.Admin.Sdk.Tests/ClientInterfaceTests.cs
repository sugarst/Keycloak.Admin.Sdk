using System.Net;
using System.Reflection;
using Keycloak.Admin.Sdk;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

[TestClass]
public sealed class ClientInterfaceTests
{
    [TestMethod]
    public void InterfaceSignaturesMatchConcreteClients()
    {
        var contract = typeof(IKeycloakAdminClient);
        var resources = contract.GetProperties();
        Assert.AreEqual(AdminEndpointCatalog.All.Select(e => e.Operation.Split('.')[0]).Distinct().Count(), resources.Length);
        int operations = 0;
        foreach (var resource in resources)
        {
            var concrete = typeof(KeycloakAdminClient).GetProperty(resource.Name)!.PropertyType;
            Assert.IsTrue(resource.PropertyType.IsInterface);
            Assert.IsTrue(resource.PropertyType.IsAssignableFrom(concrete));
            var map = concrete.GetInterfaceMap(resource.PropertyType);
            Assert.AreEqual(concrete.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Length,
                map.InterfaceMethods.Length);
            for (int i = 0; i < map.InterfaceMethods.Length; i++)
                AssertSignature(map.InterfaceMethods[i], map.TargetMethods[i]);
            operations += map.InterfaceMethods.Length;
        }
        Assert.AreEqual(AdminEndpointCatalog.All.Count, operations);
        var raw = typeof(KeycloakAdminClient).GetInterfaceMap(contract);
        var methods = raw.InterfaceMethods.Select((method, index) => (method, raw.TargetMethods[index]))
            .Where(pair => !pair.method.IsSpecialName).ToArray();
        Assert.AreEqual(6, methods.Length);
        foreach (var (method, implementation) in methods) AssertSignature(method, implementation);
    }

    [TestMethod]
    public async Task BusinessServiceCanMockAResourceThroughClientInterface()
    {
        using var cancellation = new CancellationTokenSource();
        var user = new UserRepresentation { Username = "new-user", Enabled = true };
        var response = new AdminResponse(HttpStatusCode.Created, new Uri("/users/new-user", UriKind.Relative),
            new Dictionary<string, string[]>(), []);
        var users = new Mock<IUsersApi>(MockBehavior.Strict);
        users.Setup(api => api.CreateUserAsync("demo", user, cancellation.Token)).ReturnsAsync(response);
        var client = new Mock<IKeycloakAdminClient>(MockBehavior.Strict);
        client.SetupGet(sdk => sdk.Users).Returns(users.Object);

        var service = new UserCreator(client.Object);
        Assert.AreSame(response, await service.CreateAsync("demo", user, cancellation.Token));
        client.VerifyGet(sdk => sdk.Users, Times.Once);
        users.Verify(api => api.CreateUserAsync("demo", user, cancellation.Token), Times.Once);
        client.VerifyNoOtherCalls();
        users.VerifyNoOtherCalls();
    }

    private static void AssertSignature(MethodInfo contract, MethodInfo implementation)
    {
        Assert.AreEqual(contract.Name, implementation.Name);
        Assert.AreEqual(contract.ReturnType.ToString(), implementation.ReturnType.ToString());
        var expected = contract.GetParameters();
        var actual = implementation.GetParameters();
        Assert.AreEqual(expected.Length, actual.Length);
        for (int i = 0; i < expected.Length; i++)
        {
            Assert.AreEqual(expected[i].Name, actual[i].Name);
            Assert.AreEqual(expected[i].ParameterType.ToString(), actual[i].ParameterType.ToString());
            Assert.AreEqual(expected[i].IsOptional, actual[i].IsOptional);
            Assert.AreEqual(expected[i].HasDefaultValue, actual[i].HasDefaultValue);
            Assert.AreEqual(expected[i].DefaultValue, actual[i].DefaultValue);
        }
    }

    private sealed class UserCreator(IKeycloakAdminClient sdk)
    {
        public Task<AdminResponse> CreateAsync(string realm, UserRepresentation user, CancellationToken ct)
            => sdk.Users.CreateUserAsync(realm, user, ct);
    }
}
