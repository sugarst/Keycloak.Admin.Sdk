# 26.8.1-preview.3 手动上传清单（维护者使用，不放进博客正文）

## 文件与发布口径

- 可公开的博客正文：`docs/blog/26.8.1-preview.3-release.md`。
- 博客按维护者要求，直接采用“26.8.1-preview.3 已发布到 NuGet”的口径，适合四包实际发布并可安装后公开。
- 维护者已确认手动上传，四个 preview.3 版本已通过 NuGet 官方注册元数据核对；公开说明见 [中英文发布说明](release-notes.md)。本清单保留候选路径及上传前文件哈希，候选的 `local-candidate` / `published=false` 为历史状态，不代表当前未发布。
- 对应当前分支重新生成的成功候选，源码指纹：`08658c88f857619ff947e05dcc5d5ff4d278aaf4bce3cf4bc16d02a4be56728f`。工程结构与中英文说明见 [工程结构](../../project-architecture.md)。

## 1. 优先使用已经完成验收的四包

本次完整 `Release.cs --bootstrap` 已生成的候选目录：

```text
artifacts/releases/26.8.1-preview.3/08658c88f857619ff947e05dcc5d5ff4d278aaf4bce3cf4bc16d02a4be56728f/
```

Hosting 的 35 项测试使源码方法、行和分支覆盖率均达到 100%，三项发布门槛均固定为 100%。

本次通过 728 项测试（核心 567、协议 96、Hosting 35、Platform 5、工程与证据 25）、双路线 Admin 业务验收、标准/兼容应用协议、六套非 Stable 受保护复验及实际包消费。

该目录中的四个 `.nupkg` 与 `release-manifest.json` 属于同一次成功候选。建议从这个目录选择上传文件，避免混入其他尝试产生的同版本包。完整记录：

```text
docs/releases/26.8.1-preview.3/08658c88f857619ff947e05dcc5d5ff4d278aaf4bce3cf4bc16d02a4be56728f.json
```

| 建议上传顺序 | 包文件 | SHA-256 |
| --- | --- | --- |
| 1 | `Keycloak.Admin.Sdk.26.8.1-preview.3.nupkg` | `b586aa7b57d60b6a7df9da113b29d99abe388b84d9b4b9c7b19a8581ff918a18` |
| 2 | `Keycloak.Admin.Sdk.Protocols.26.8.1-preview.3.nupkg` | `1d01b8fced7a1d62fdc6ec6a62dff6bef0e06fea0a017f860cf3f97abfd2d900` |
| 3 | `Keycloak.Admin.Sdk.Hosting.26.8.1-preview.3.nupkg` | `02ce31f774f50b4256db72d639910ef984189409536f70bf2428f61ca3719999` |
| 4 | `Keycloak.Admin.Sdk.Platform.26.8.1-preview.3.nupkg` | `75c13e01c720f13a82fc31420151bcae2c43f378ba8a3c6ad82c4a1cfeab9c6f` |

Hosting 与 Platform 互不依赖，二者的先后可以交换。优先发布主包和 Protocols，等依赖包可见后再发布两个扩展包。

上传前在仓库根目录核对文件：

```powershell
$candidate = Join-Path $PWD 'artifacts/releases/26.8.1-preview.3/08658c88f857619ff947e05dcc5d5ff4d278aaf4bce3cf4bc16d02a4be56728f'
$manifest = Get-Content -Raw (Join-Path $candidate 'release-manifest.json') | ConvertFrom-Json

if (!$manifest.allGatesPassed -or $manifest.packageVersion -ne '26.8.1-preview.3') {
    throw '候选版本或验收状态不符合预期。'
}

foreach ($package in $manifest.packages) {
    $path = Join-Path $candidate $package.file
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $package.sha256) {
        throw "候选文件哈希不匹配：$($package.file)"
    }
    Write-Output "PASS $($package.file)"
}
```

候选中的 `sdkCommit` 为 `7a079506da369dff1829fd8fedad53659926a7e4`，是启动完整 Release 时的 HEAD。`sdkWorkingTreeDirty=true` 如实记录了重建中更新的目录与验收证据；应结合源码指纹、后续保存证据的 Git 提交和包哈希确认来源，不要手工修改候选中的来源字段。

## 2. 在 NuGet.org 手动上传

1. 登录具有这些包发布权限的 [NuGet.org](https://www.nuget.org/)。
2. 使用网站的包上传入口，按上述依赖顺序逐个选择候选目录中的 `.nupkg`。
3. 在预览信息中确认 Package ID、`26.8.1-preview.3`、许可证、README 和依赖清单。
4. 完成四包上传后，检查每个版本页面，并等待包可被客户端恢复。
5. 在新建的验证项目中按需安装或分别验证四包。不要用旧项目缓存中的同版本本地包代替公开源验证。

公开版本链接：

- [Keycloak.Admin.Sdk](https://www.nuget.org/packages/Keycloak.Admin.Sdk/26.8.1-preview.3)
- [Keycloak.Admin.Sdk.Protocols](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Protocols/26.8.1-preview.3)
- [Keycloak.Admin.Sdk.Hosting](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Hosting/26.8.1-preview.3)
- [Keycloak.Admin.Sdk.Platform](https://www.nuget.org/packages/Keycloak.Admin.Sdk.Platform/26.8.1-preview.3)

## 3. 如果需要重新构建

如果当前候选文件仍与清单匹配，无需为撰写博客重新打包。

需要新候选时，先确认四个项目仍使用 `26.8.1-preview.3`，不要混用新旧版本。执行完整流程：

```shell
dotnet run --file tools/Release.cs
```

需要重新建立基础业务证据时，按仓库流程使用 `-- --bootstrap`。实现或验证输入发生变化后，先重跑应用协议和非 Stable 功能的验证、独立晋升；完整覆盖门禁不会接受失效证据。

只做开发打包时，可以使用博客正文中的 `dotnet build` / `dotnet pack` 命令。该操作不能代替完整验收，新生成的包也不能直接套用上面的旧哈希。重新构建可能因来源元数据等差异改变包内容，应使用新成功候选对应的记录。

## 4. 实际发布后同步仓库

- 按 `docs/releases/README.md` 的格式补充 preview.3 的 `publication.json`，记录实际发布时间、NuGet 链接、包 SHA-256、对应候选和实现提交。
- 更新根 README、英文 README 和 CHANGELOG 中 preview.3 的“开发中／未发布”描述。
- 候选记录继续保留 `local-candidate`、`published=false` 的历史事实；另用 publication 记录实际发布，不覆盖原始验收记录。
- 四包均已可安装后，再公开博客正文。

本清单不执行推送、打 tag、GitHub Release 或 NuGet 上传；这些操作可在实际发布阶段按维护者选择进行。
