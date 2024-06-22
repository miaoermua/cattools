# cattools

基于 BASH 编写的 CatWrt 工具箱，帮助用户轻松实现各种实用功能。

Blog(待完善): <https://www.miaoer.xyz/posts/network/catwrt-bash-script>

执行下列命令一键安装 Cattools，安装后输入 `cattools` 或 `/usr/bin/cattools` 并回车即可使用。

```bash
curl https://raw.githubusercontent.com/miaoermua/cattools/main/install.sh | bash
```

执行以下任意命令在线使用 Cattools

```bash
curl https://raw.githubusercontent.com/miaoermua/cattools/main/cattools.sh | bash

# curl https://fastly.jsdelivr.net/gh/miaoermua/cattools@main/cattools.sh | bash
```

## Todo

- [x] 1. SetIP                           -  设置 IP
- [x] 2. network_wizard                  -  网络向导
- [x] 3. Debug                           -  抓取日志
- [x] 4. catwrt_update                   -  检查更新
- [x] 5. use_repo                        -  启用软件源
- [x] 6. sysupgrade                      -  系统更新(未经测试)
- [x] 7. diagnostics                     -  网络诊断
- [x] 0. Exit                            -  退出
- [x] 热更新和安装脚本
- [x] 命令行参数
- [ ] 预设 Wi-FI 配置(wireless)
- [ ] 实现对旁路网关(旁路由)配置
- [ ] 升级插件(升级系统后)
- [ ] 插件商店
