using System.Text.RegularExpressions;

internal sealed record JavaMethod(string Class, string Name, string ReturnType, string Annotations, string Parameters, string Body, string File, int Line);
internal sealed record JavaRoute(string Verb, string Path, JavaMethod Method);

// A deliberately small source index, not a Java compiler. Unresolved locators are emitted for review.
internal sealed class JavaRoutes
{
    private readonly Dictionary<string, List<JavaMethod>> methods = new();
    private readonly Dictionary<string, string> parents = new();
    public List<string> Unresolved { get; } = [];
    public List<string> SourceFiles { get; } = [];
    public List<JavaRoute> Variants { get; } = [];

    public JavaRoutes(string root, bool uiOnly = false)
    {
        foreach (var file in Directory.EnumerateFiles(root, "*.java", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (!relative.Contains("/src/main/java/") || relative.StartsWith("tests") || relative.Contains("/test")) continue;
            if (uiOnly ? !relative.StartsWith("rest/admin-ui-ext/") : !relative.Contains("/resources/admin/") && !relative.Contains("/authorization/admin/") && !relative.Contains("/organization/admin/") && !relative.Contains("/workflow/admin/") && !relative.Contains("/ssf/services/admin/")) continue;
            var text = File.ReadAllText(file);
            var classMatch = Regex.Match(text, @"\bpublic\s+(?:(?:abstract|final)\s+)?(?:class|interface)\s+(\w+)(?:\s+extends\s+(\w+))?");
            if (!classMatch.Success) continue;
            SourceFiles.Add(relative);
            string name = classMatch.Groups[1].Value;
            if (classMatch.Groups[2].Success) parents[name] = classMatch.Groups[2].Value;
            var noComments = Regex.Replace(text, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|/\\*[\\s\\S]*?\\*/|//[^\\r\\n]*", m => m.Value.StartsWith('/') ? new string(' ', m.Length) : m.Value);
            var clean = noComments.ToCharArray();
            // Blank annotations while preserving offsets, including nested annotation arguments.
            foreach (Match a in Regex.Matches(noComments, @"@[\w.]+"))
            {
                if (clean[a.Index] == ' ') continue;
                int end = a.Index + a.Length;
                while (end < text.Length && char.IsWhiteSpace(noComments[end])) end++;
                if (end < text.Length && noComments[end] == '(') end = End(noComments, end, '(', ')') + 1;
                for (int i = a.Index; i < end; i++) clean[i] = ' ';
            }
            string stripped = new(clean);
            int boundary = text.IndexOf('{', classMatch.Index) + 1;
            var list = new List<JavaMethod>();
            foreach (Match m in Regex.Matches(stripped, @"\b(?:public|protected)\s+(?:(?:static|final|synchronized)\s+)*(?<type>[\w.<>?,\[\] ]+?)\s+(?<name>\w+)\s*\("))
            {
                if (m.Index < boundary) continue;
                int startParams = m.Index + m.Length - 1;
                int endParams = End(stripped, startParams, '(', ')');
                int bodyStart = stripped.IndexOfAny(['{', ';'], endParams);
                if (bodyStart < 0) continue;
                int bodyEnd = stripped[bodyStart] == '{' ? End(stripped, bodyStart, '{', '}') : bodyStart;
                // Field initializers and constructors before the method are harmless: annotations are filtered below.
                string annotations = noComments[boundary..m.Index];
                list.Add(new(name, m.Groups["name"].Value, m.Groups["type"].Value.Trim(), annotations,
                    noComments[(startParams + 1)..endParams], noComments[bodyStart..(bodyEnd + 1)],
                    Path.GetRelativePath(root, file).Replace('\\', '/'), text[..m.Index].Count(c => c == '\n') + 1));
                boundary = bodyEnd + 1;
            }
            methods[name] = list;
        }
    }

    public List<JavaRoute> Discover(bool uiOnly = false)
    {
        var routes = new List<JavaRoute>();
        if (uiOnly)
        {
            Visit("AdminExtResource", "/admin/realms/{realm}/ui-ext", [], routes);
            var uiRoutes = routes.Select(r => r with { Method = r.Method with { Class = "Ui" + r.Method.Class } }).ToList();
            Variants.AddRange(uiRoutes);
            return uiRoutes;
        }
        Visit("RealmsAdminResource", "/admin/realms", [], routes);
        Visit("ServerInfoAdminResource", "/admin/serverinfo", [], routes);
        foreach (var (type, members) in methods)
        {
            var id = members.FirstOrDefault(m => m.Name == "getId");
            var resource = members.FirstOrDefault(m => m.Name == "getResource" && !m.Annotations.Contains("@Path"));
            if (id is null || resource is null) continue;
            var literal = Regex.Match(id.Body, "return\\s+\"([^\"]+)\"");
            var target = Regex.Match(resource.Body, @"return\s+new\s+(\w+)");
            if (literal.Success && target.Success && methods.ContainsKey(target.Groups[1].Value))
                Visit(target.Groups[1].Value, "/admin/realms/{realm}/" + literal.Groups[1].Value, [], routes);
        }
        Visit("SsfAdminResource", "/admin/realms/{realm}/ssf", [], routes);
        Variants.AddRange(routes);
        return routes.DistinctBy(r => r.Verb + " " + r.Path).OrderBy(r => r.Path, StringComparer.Ordinal).ThenBy(r => r.Verb).ToList();
    }

    private IEnumerable<JavaMethod> Members(string type)
    {
        if (!methods.TryGetValue(type, out var own)) return [];
        var all = own.AsEnumerable();
        if (parents.TryGetValue(type, out var parent)) all = all.Concat(Members(parent).Where(m => !own.Any(o => o.Name == m.Name)));
        return all;
    }

    private void Visit(string type, string prefix, HashSet<string> chain, List<JavaRoute> routes)
    {
        if (!chain.Add(type)) { Unresolved.Add($"cycle {prefix} -> {type}"); return; }
        foreach (var m in Members(type))
        {
            var pathMatch = Regex.Match(m.Annotations, "@Path\\(\\s*\"([^\"]*)\"\\s*\\)");
            var verb = Regex.Match(m.Annotations, @"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b");
            string path = pathMatch.Success ? prefix.TrimEnd('/') + "/" + pathMatch.Groups[1].Value.Trim('/') : prefix;
            if (verb.Success) routes.Add(new(verb.Groups[1].Value, path, m));
            else if (pathMatch.Success)
            {
                string target = m.ReturnType;
                if (!methods.ContainsKey(target))
                {
                    var news = Regex.Matches(m.Body, @"new\s+(\w+)\s*\(").Select(x => x.Groups[1].Value)
                        .Where(n => methods.ContainsKey(n) && Members(n).Any(x => Regex.IsMatch(x.Annotations, @"@(Path|GET|POST|PUT|DELETE)\b"))).Distinct().ToArray();
                    if (news.Length == 1) target = news[0];
                    else if (type is "PolicyService" or "PermissionService" && m.Name == "getResource")
                    {
                        Visit("PolicyResourceService", path, new(chain), routes);
                        Visit("PolicyTypeService", path, new(chain), routes);
                        continue;
                    }
                }
                if (type == "PolicyTypeService" && m.Name == "getResource")
                {
                    path = prefix.TrimEnd('/') + "/{policy-id}";
                    Visit("PolicyTypeResourceService", path, new(chain), routes);
                    continue;
                }
                if (methods.ContainsKey(target)) Visit(target, path, new(chain), routes);
                else Unresolved.Add($"{path} -> {type}.{m.Name}: {target} ({m.File}:{m.Line})");
            }
        }
    }

    internal static int End(string text, int start, char open, char close)
    {
        int depth = 0;
        char quote = '\0';
        for (int i = start; i < text.Length; i++)
        {
            char c = text[i];
            if (quote != '\0') { if (c == '\\') i++; else if (c == quote) quote = '\0'; continue; }
            if (c is '\"' or '\'') { quote = c; continue; }
            if (c == open) depth++;
            if (c == close) depth--;
            if (c == close && depth == 0) return i;
        }
        throw new InvalidDataException($"Unbalanced {open} at {start}");
    }

}
