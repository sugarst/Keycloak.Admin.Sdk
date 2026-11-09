# 26.8.1-preview.3 手动上传清单（维护者使用，不放进博客正文）

## 文件与发布口径

- 可公开的博客正文：`docs/blog/26.8.1-preview.3-release.md`。
- 博客按维护者要求，直接采用“26.8.1-preview.3 已发布到 NuGet”的口径，适合四包实际发布并可安装后公开。
- 本清单只说明手动操作。完整候选已通过验收并生成四包，NuGet 尚未上传，状态保持 `local-candidate` / `published=false`。
- 对应本次工程整理后的成功候选，源码指纹：`26cc27b4007fba61b31df93be4d3432235abd85d24a282a8141cd89b8ccd3faa`。工程结构与中英文说明见 [工程结构](../../project-architecture.md)。

## 1. 优先使用已经完成验收的四包

本次完整 `Release.cs --bootstrap` 已生成的候选目录：

```text
artifacts/releases/26.8.1-preview.3/26cc27b4007fba61b31df93be4d3432235abd85d24a282a8141cd89b8ccd3faa/
```

本次通过 707 项测试（核心 567、协议 96、Hosting 14、Platform 5、工程与证据 25）、双路线 Admin 业务验收、标准/兼容应用协议、六套非 Stable 受保护复验及实际包消费。

该目录中的四个 `.nupkg` 与 `release-manifest.json` 属于同一次成功候选。建议从这个目录选择上传文件，避免混入其他尝试产生的同版本包。完整记录：

```text
docs/releases/26.8.1-preview.3/26cc27b4007fba61b31df93be4d3432235abd85d24a282a8141cd89b8ccd3faa.json
```

| 建议上传顺序 | 包文件 | SHA-256 |
| --- | --- | --- |
| 1 | `Keycloak.Admin.Sdk.26.8.1-preview.3.nupkg` | `c6fe9fd07093668a953b4a189acac521484fa2618b86da319a28ad22dd6ed9c8` |
| 2 | `Keycloak.Admin.Sdk.Protocols.26.8.1-preview.3.nupkg` | `1b0225a90248b373c014bd58ab203c0db757903c6b644af686e739e9100c6aa3` |
| 3 | `Keycloak.Admin.Sdk.Hosting.26.8.1-preview.3.nupkg` | `5a6b93945398e26643d825fb5d46bd142931156a59f29e6f8465c4c3e11d65a6` |
| 4 | `Keycloak.Admin.Sdk.Platform.26.8.1-preview.3.nupkg` | `78fa0742d4e9a5aa1e52c768d4293fab8889cde144f5e094463c92368af6d229` |

Hosting 与 Platform 互不依赖，二者的先后可以交换。优先发布主包和 Protocols，等依赖包可见后再发布两个扩展包。

上传前在仓库根目录核对文件：

```powershell
$candidate = Join-Path $PWD 'artifacts/releases/26.8.1-preview.3/26cc27b4007fba61b31df93be4d3432235abd85d24a282a8141cd89b8ccd3faa'
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

候选中的 `sdkCommit` 是启动验收时的 HEAD，`sdkWorkingTreeDirty=true` 如实记录了工程整理尚未提交的状态。实现、当前证据和新候选记录会一起提交；应结合源码指纹、对应 Git 提交和包哈希确认来源，不要手工修改候选中的来源字段。

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
