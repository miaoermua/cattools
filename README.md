# cattools

基于 BASH 编写的 CatWrt 工具箱，帮助用户轻松实现各种实用功能。

Blog(待完善): <https://www.miaoer.xyz/posts/network/catwrt-bash-script>

执行下列命令 **一键安装 Cattools**，安装后输入 `cattools` 或 `/usr/bin/cattools` 并回车即可使用。

```bash
curl https://raw.githubusercontent.com/miaoermua/cattools/main/install.sh | bash
```

## Todo

- [x] 热更新和安装脚本
- [x] 命令行参数
- [x] 1. SetIP                           -  设置 IP
- [x] 2. Network_Wizard                  -  网络向导(旁路网关)
- [x] 3. Debug                           -  抓取日志
- [x] 4. Catwrt_Update                   -  检查更新
- [x] 5. Apply_Repo                      -  软件源配置
- [x] 6. Sysupgrade                      -  系统更新
- [x] 7. Diagnostics                     -  网络诊断
- [x] 8. Reinstalld_packages             -  软件包恢复(升级系统后)
- [x] 9. Enhancement                     -  实用增强
- [x]  |——  1. Mihomo 配置
- [x]  |——  2. Tailscale 配置
- [x]  |——  3. TTYD 配置(危险)
- [x]  |——  4. SSL/TLS 上传 zip 证书配置
- [x]  |——  5. 重置密码
- [x]  |——  6. 重置系统
- [x] 0. Exit                            -  退出

喵二的*大饼* 新建文件夹中...

- [ ] 预设 Wi-FI 配置(wireless) - 位于 网络向导
- [ ] mt798x 系列升级系统 - 位于 系统更新
- [ ] 插件商店 - 位于实用增强
- [ ] 自动挂载扩容 - 位于实用增强
- [ ] NAS 快速配置(SMB) - 位于实用增强
