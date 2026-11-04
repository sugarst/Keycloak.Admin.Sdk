using System.Text.RegularExpressions;

// Independent token-level declaration scan. Does not use the SDK generator's JavaRoutes parser.
internal sealed record AuditToken(string Text, int Start, int End, bool Literal = false);
internal sealed record AuditAnnotation(string Name, IReadOnlyList<AuditToken> Arguments);
internal sealed record AuditMethod(AuditClass Owner, string Name, string ReturnType, string Parameters, string Body,
    List<AuditAnnotation> Annotations, string Signature, int Line);
internal sealed record AuditRoute(string Verb, string Path, AuditMethod Method);
internal sealed record AuditParameter(string Name, string Type, string Binding, string WireName);
internal sealed class AuditClass(string name, string package, string file, string text)
{
    public string Name { get; } = name;
    public string Package { get; } = package;
    public string QualifiedName => Package + "." + Name;
    public string File { get; } = file;
    public string Text { get; } = text;
    public string Parent { get; set; } = "";
    public Dictionary<string, string> Imports { get; } = new(StringComparer.Ordinal);
    public List<AuditMethod> Methods { get; } = [];
}

internal sealed class JavaAuditIndex
{
    public Dictionary<string, AuditClass> Classes { get; } = new(StringComparer.Ordinal);
    public List<string> Unresolved { get; } = [];
    public List<AuditRoute> Variants { get; } = [];

    public JavaAuditIndex(string source)
    {
        foreach (string file in Directory.EnumerateFiles(source, "*.java", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(source, file).Replace('\\', '/');
            if (!relative.Contains("/src/main/java/", StringComparison.Ordinal) || relative.StartsWith("tests", StringComparison.Ordinal)) continue;
            string text = File.ReadAllText(file);
            if (!text.Contains("@Path", StringComparison.Ordinal) && !Regex.IsMatch(text, @"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
                && !relative.Contains("/admin/", StringComparison.Ordinal) && !text.Contains("AdminRealmResourceProvider", StringComparison.Ordinal)) continue;
            try { Parse(relative, text); }
            catch (InvalidDataException error) { throw new InvalidDataException(relative + ": " + error.Message, error); }
        }
    }

    private void Parse(string file, string text)
    {
        var tokens = Lex(text);
        int classIndex = -1;
        for (int i = 0; i < tokens.Count; i++)
            if (!tokens[i].Literal && tokens[i].Text is "class" or "interface" && (i == 0 || tokens[i - 1].Text != ".")) { classIndex = i; break; }
        int packageIndex = tokens.FindIndex(t => t.Text == "package");
        if (classIndex < 0 || packageIndex < 0 || tokens[classIndex + 1].Literal) return;
        string package = string.Concat(tokens.Skip(packageIndex + 1).TakeWhile(t => t.Text != ";").Select(t => t.Text));
        var type = new AuditClass(tokens[classIndex + 1].Text, package, file, text);
        int start = tokens.FindIndex(classIndex, t => t.Text == "{");
        if (start < 0) return;
        int parentIndex = tokens.FindIndex(classIndex, start - classIndex, t => t.Text == "extends");
        if (parentIndex >= 0) type.Parent = tokens[parentIndex + 1].Text;
        for (int i = 0; i < classIndex; i++)
        {
            if (tokens[i].Text != "import") continue;
            string imported = string.Concat(tokens.Skip(i + 1).TakeWhile(t => t.Text != ";").Select(t => t.Text));
            if (!imported.StartsWith("static", StringComparison.Ordinal) && !imported.EndsWith('*')) type.Imports[imported.Split('.').Last()] = imported;
        }
        Classes[type.QualifiedName] = type;
        int chunk = start + 1;
        for (int i = chunk; i < tokens.Count && tokens[i].Text != "}";)
        {
            int parentheses = 0;
            int end = i;
            for (; end < tokens.Count; end++)
            {
                string value = tokens[end].Text;
                if (tokens[end].Literal) continue;
                if (value == "(") parentheses++;
                else if (value == ")") parentheses--;
                if (parentheses == 0 && value is ";" or "{") break;
            }
            if (end >= tokens.Count) break;
            int closing = tokens[end].Text == "{" ? Match(tokens, end, "{", "}") : end;
            var header = tokens.GetRange(i, end - i);
            var annotations = new List<AuditAnnotation>();
            var bare = WithoutAnnotations(header, annotations);
            int open = bare.FindIndex(t => t.Text == "(");
            if (open > 0 && bare.Any(t => t.Text is "public" or "protected") && !bare.Take(open).Any(t => t.Text == "="))
            {
                int close = Match(bare, open, "(", ")");
                string name = bare[open - 1].Text;
                if (name != type.Name)
                {
                    int access = bare.FindIndex(t => t.Text is "public" or "protected");
                    int ret = access + 1;
                    while (ret < open - 1 && bare[ret].Text is "static" or "final" or "synchronized" or "abstract") ret++;
                    string returnType = string.Concat(bare.Skip(ret).Take(open - ret - 1).Select(t => t.Text));
                    int originalOpen = header.FindIndex(t => t.Start == bare[open].Start);
                    int originalClose = Match(header, originalOpen, "(", ")");
                    string parameters = text[header[originalOpen].End..header[originalClose].Start];
                    string signature = name + "(" + string.Concat(bare.Skip(open + 1).Take(close - open - 1).Select(t => t.Text)) + ")";
                    int line = text[..bare[access].Start].Count(c => c == '\n') + 1;
                    type.Methods.Add(new(type, name, returnType, parameters, text[tokens[end].Start..tokens[closing].End], annotations, signature, line));
                }
            }
            i = closing + 1;
        }
    }

    public List<AuditRoute> Discover()
    {
        Visit(Classes["org.keycloak.services.resources.admin.AdminRoot"], "/admin", []);
        foreach (var factory in Classes.Values)
        {
            if (!factory.Text.Contains("implements AdminRealmResourceProviderFactory", StringComparison.Ordinal)) continue;
            var id = factory.Methods.FirstOrDefault(m => m.Name == "getId");
            if (id is null) continue;
            var literal = Regex.Match(id.Body, "return\\s+\"([^\"]+)\"");
            if (!literal.Success) { Unresolved.Add("factory id: " + factory.QualifiedName); continue; }
            var resource = factory.Methods.FirstOrDefault(m => m.Name == "getResource");
            if (resource is null)
            {
                var create = factory.Methods.FirstOrDefault(m => m.Name == "create");
                var provider = create is null ? null : NewResources(create, requireRest: false).FirstOrDefault();
                resource = provider?.Methods.FirstOrDefault(m => m.Name == "getResource");
            }
            if (resource is null) { Unresolved.Add("factory resource: " + factory.QualifiedName); continue; }
            var targets = NewResources(resource).ToArray();
            if (targets.Length != 1) { Unresolved.Add("factory target: " + factory.QualifiedName); continue; }
            Visit(targets[0], "/admin/realms/{realm}/" + literal.Groups[1].Value, []);
        }
        return Variants.DistinctBy(r => r.Verb + " " + Canonical(r.Path)).OrderBy(r => r.Path, StringComparer.Ordinal).ThenBy(r => r.Verb, StringComparer.Ordinal).ToList();
    }

    private void Visit(AuditClass type, string prefix, HashSet<string> chain)
    {
        if (!chain.Add(type.QualifiedName)) { Unresolved.Add("recursive locator: " + prefix + " -> " + type.QualifiedName); return; }
        foreach (var method in Members(type))
        {
            string? suffix = method.Annotations.FirstOrDefault(a => a.Name == "Path")?.Arguments.FirstOrDefault(t => t.Literal)?.Text;
            string path = suffix is null ? prefix : prefix.TrimEnd('/') + "/" + suffix.Trim('/');
            // Admin console assets, redirects and CORS are explicitly outside the Admin REST scope.
            if (!path.StartsWith("/admin/realms", StringComparison.Ordinal) && !path.StartsWith("/admin/serverinfo", StringComparison.Ordinal)) continue;
            string? verb = method.Annotations.Select(a => a.Name).FirstOrDefault(a => a is "GET" or "POST" or "PUT" or "DELETE" or "PATCH" or "HEAD");
            if (verb is not null) { Variants.Add(new(verb, path, method)); continue; }
            if (suffix is null) continue;
            if (method.Owner.Name == "RealmAdminResource" && method.Name == "extension") { Unresolved.Add("dynamic SPI: " + path); continue; }
            if (method.Name == "getPolicyAdminResourceProvider") { Unresolved.Add("policy provider SPI: " + path); continue; }
            if (method.Owner.Name == "PolicyService" && method.Name == "getResource")
            {
                if (type.Name == "PolicyTypeService")
                    Visit(Classes["org.keycloak.authorization.admin.PolicyTypeResourceService"], prefix.TrimEnd('/') + "/{policy-id}", new(chain));
                else
                {
                    Visit(Classes["org.keycloak.authorization.admin.PolicyResourceService"], path, new(chain));
                    Visit(Classes["org.keycloak.authorization.admin.PolicyTypeService"], path, new(chain));
                }
                continue;
            }
            var target = Resolve(method.Owner, method.ReturnType);
            if (target is null)
            {
                var news = NewResources(method).ToArray();
                if (news.Length == 1) target = news[0];
            }
            if (target is null) Unresolved.Add("unresolved locator: " + path + " -> " + method.Owner.QualifiedName + "." + method.Name);
            else Visit(target, path, new(chain));
        }
    }

    private IEnumerable<AuditClass> NewResources(AuditMethod method, bool requireRest = true) =>
        Regex.Matches(method.Body, @"\bnew\s+(\w+)\s*\(").Select(m => Resolve(method.Owner, m.Groups[1].Value)).OfType<AuditClass>()
            .Where(t => !requireRest || Members(t).Any(m => !m.Annotations.Any(a => a.Name == "OPTIONS") && m.Annotations.Any(a => a.Name is "Path" or "GET" or "POST" or "PUT" or "DELETE")))
            .DistinctBy(t => t.QualifiedName);

    private AuditClass? Resolve(AuditClass context, string name)
    {
        if (Classes.TryGetValue(name, out var qualified)) return qualified;
        if (context.Imports.TryGetValue(name, out var imported) && Classes.TryGetValue(imported, out var match)) return match;
        return Classes.GetValueOrDefault(context.Package + "." + name);
    }

    private IEnumerable<AuditMethod> Members(AuditClass type)
    {
        var inherited = Resolve(type, type.Parent) is { } parent ? Members(parent).ToArray() : [];
        // Preserve overloads independently; compare erased parameter declarations for simple overrides.
        return type.Methods.Concat(inherited.Where(baseMethod => !type.Methods.Any(own => own.Signature == baseMethod.Signature)));
    }

    internal static string Canonical(string path) => Regex.Replace(path.TrimEnd('/'), @"\{[^}]+\}", "{}");

    internal static IEnumerable<AuditParameter> Parameters(AuditMethod method)
    {
        var tokens = Lex(method.Parameters);
        int start = 0, parentheses = 0, angles = 0, braces = 0;
        for (int i = 0; i <= tokens.Count; i++)
        {
            if (i < tokens.Count && !tokens[i].Literal)
            {
                switch (tokens[i].Text)
                {
                    case "(": parentheses++; break; case ")": parentheses--; break;
                    case "<": angles++; break; case ">": angles--; break;
                    case "{": braces++; break; case "}": braces--; break;
                }
            }
            if (i != tokens.Count && (tokens[i].Text != "," || parentheses != 0 || angles != 0 || braces != 0)) continue;
            var annotations = new List<AuditAnnotation>();
            var bare = WithoutAnnotations(tokens.GetRange(start, i - start), annotations).Where(t => t.Text != "final").ToArray();
            start = i + 1;
            if (bare.Length < 2) continue;
            string name = bare[^1].Text;
            string type = string.Concat(bare[..^1].Select(t => t.Text));
            var binding = annotations.FirstOrDefault(a => a.Name is "PathParam" or "QueryParam" or "FormParam" or "HeaderParam" or "Context" or "BeanParam" or "MultipartForm");
            string wire = binding?.Arguments.FirstOrDefault(t => t.Literal)?.Text ?? string.Concat(binding?.Arguments.Select(t => t.Text) ?? []);
            wire = wire switch { "OIDCLoginProtocol.CLIENT_ID_PARAM" => "client_id", "OIDCLoginProtocol.REDIRECT_URI_PARAM" => "redirect_uri", _ => wire };
            yield return new(name, type, binding?.Name ?? "body", wire);
        }
    }

    private static List<AuditToken> WithoutAnnotations(List<AuditToken> tokens, List<AuditAnnotation> annotations)
    {
        var result = new List<AuditToken>();
        for (int i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Text != "@") { result.Add(tokens[i]); continue; }
            string name = tokens[++i].Text;
            while (i + 2 < tokens.Count && tokens[i + 1].Text == ".") { name = tokens[i + 2].Text; i += 2; }
            var arguments = new List<AuditToken>();
            if (i + 1 < tokens.Count && tokens[i + 1].Text == "(")
            {
                int end = Match(tokens, i + 1, "(", ")");
                arguments.AddRange(tokens.Skip(i + 2).Take(end - i - 2));
                i = end;
            }
            annotations.Add(new(name, arguments));
        }
        return result;
    }

    private static int Match(List<AuditToken> tokens, int start, string open, string close)
    {
        int depth = 0;
        for (int i = start; i < tokens.Count; i++)
        {
            if (tokens[i].Literal) continue;
            if (tokens[i].Text == open) depth++;
            else if (tokens[i].Text == close && --depth == 0) return i;
        }
        throw new InvalidDataException("Unbalanced Java declaration at " + tokens[start].Start);
    }

    internal static List<AuditToken> Lex(string text)
    {
        var tokens = new List<AuditToken>();
        for (int i = 0; i < text.Length;)
        {
            if (char.IsWhiteSpace(text[i])) { i++; continue; }
            if (i + 1 < text.Length && text[i] == '/' && text[i + 1] == '/') { while (i < text.Length && text[i] != '\n') i++; continue; }
            if (i + 1 < text.Length && text[i] == '/' && text[i + 1] == '*')
            {
                int end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? text.Length : end + 2;
                continue;
            }
            int start = i;
            if (text[i] is '\"' or '\'')
            {
                char quote = text[i++];
                if (quote == '\"' && i + 1 < text.Length && text[i] == '\"' && text[i + 1] == '\"')
                {
                    int end = text.IndexOf("\"\"\"", i + 2, StringComparison.Ordinal);
                    i = end < 0 ? text.Length : end + 3;
                    tokens.Add(new(text[start..i], start, i, true));
                    continue;
                }
                while (i < text.Length && text[i] != quote) { if (text[i] == '\\') i++; i++; }
                if (i < text.Length) i++;
                tokens.Add(new(text[(start + 1)..(i - 1)], start, i, true));
            }
            else if (char.IsLetterOrDigit(text[i]) || text[i] is '_' or '$')
            {
                while (i < text.Length && (char.IsLetterOrDigit(text[i]) || text[i] is '_' or '$')) i++;
                tokens.Add(new(text[start..i], start, i));
            }
            else { tokens.Add(new(text[i].ToString(), i, i + 1)); i++; }
        }
        return tokens;
    }
}
