# 贡献指南 (Contributing Guide)

感谢你对本项目的关注与贡献！

## 许可证 (License)

本项目采用 **GNU Affero General Public License v3.0 (AGPLv3)**（OSI 认证的强互惠许可证）。

任何对项目的使用、修改与分发都必须遵守 AGPLv3 的条款。特别地，如果你将本项目（或基于它的修改版）通过计算机网络对外提供服务（SaaS / 云服务），你必须向所有用户公开完整的服务端源代码。

商业使用或希望获得 AGPLv3 之外的授权，请联系项目维护者。

## 开发者原产地证书 (DCO)

本项目采用 **Developer Certificate of Origin (DCO)** 机制（而非 CLA）。

在提交代码之前，请确认你同意 [Developer Certificate of Origin](https://developercertificate.org/) 的条款：

> By making a contribution to this project, I certify that:
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications; or
> (c) The contribution was provided directly to me by some other person who certified (a) or (b) and I have not modified it.
> (d) I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

### 如何签名 (How to sign off)

每个提交信息中必须包含 `Signed-off-by` 行，格式为：

```
Signed-off-by: 你的名字 <你的邮箱>
```

最简单的方式是提交时加上 `-s` 参数：

```bash
git commit -s
```

Git 会自动追加 `Signed-off-by` 行。CI 会检查每个 PR 的所有提交是否都包含签名，未签名的 PR 将无法合并。

> 注意：请使用与你的 GitHub 账号关联的邮箱进行签名。
