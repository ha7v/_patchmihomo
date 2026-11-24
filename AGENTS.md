# AGENTS.md

本文件记录 `droid_lkm`（上游 `Dere3046/_patchHarmony`）的开发环境事实、技术约束与本地工具用法，供协作时参考。

## 1. 维护范围与目标设备

- 架构体系基于 KMSDK、KallRecon、Type_info、KernCall、HooKern 与 vendorcompat；能力判断优先基于符号、`System.map`、运行时 BTF 或锚点探测，尽量避免硬编码内核版本号。
- 优先测试与适配设备（详情见 `docs/DEVICES.md`）：
  - 本机：OnePlus 13（`android15-6.6`，PJZ110 / SM8750）— 当前工作区位于该设备。
  - 另一台测试机：一加平板 Pro（`android14-6.1`）。
- 上游兼容矩阵：`android12-5.10` ~ `android17-6.18`，打包变体包括 `standard`、`native`（`DROID_LKM_NATIVE_PID=1`）和 `both`（`DROID_LKM_PID_BOTH=1`）。

## 2. 本机环境事实与操作边界

当前工作区运行在目标 Android 设备的 Termux 环境中，本地无内核编译工具链。

- **只读与测试权限**：
  - 允许使用 `su` 执行只读检查（如 `/proc/droid_lkm/features`、`/proc/droid_lkm_misc/status`、`/proc/modules`、`/proc/kallsyms`、`/proc/config.gz`、`/sys/kernel/btf/vmlinux`、`/sys/module/droid_lkm*/parameters/*`、`/data/adb/phdroid/` 状态与日志、`dmesg`）。
  - **崩溃 / Kernel Panic 日志排查路径（只读）**：
    - OnePlus / OPLUS（如本机 OP13）：`/data/persist_log/backup/SYSTEM_LAST_KMSG.txt`（上次异常重启完整 kmsg 与 Call trace）、`/data/persist_log/criticallog/persist/critical.log`（`<kernel-panic-begin>` 摘要）、`/data/persist_log/DCS/minidump/`（`device.info` / `minidump.bin`）、`/data/vendor/ramdump/`、`/data/vendor/olog/`。
    - 通用 Android / 其他高通或 OEM 机型：`/sys/fs/pstore/`、`/proc/last_kmsg`、`/data/vendor/diag/`（注：本机 OP13 无 `/data/vendor/diag/`，崩溃日志归集在 `/data/persist_log/`）。
  - 需要 root 权限运行 Python 脚本时，使用 `sudo python3`（Termux 的 `agnostic-apollo/sudo` 会保留 `PATH` 和 `LD_LIBRARY_PATH`；直接 `su -c python3` 可能缺少动态库）。
  - 可使用 `sudo python3` 在宿主、或通过 `ssh lyra` 在 Droidspaces Debian 容器内（含 `gcc`、`python3`、`bwrap`、`strace`、`readelf`、`objdump`）执行无害的临时子进程用户态测试。注意确认本机当前加载的 LKM 版本，**不要在未修补的老版本 LKM 上直接跑 `test-runtime.py --stress`**（故障注入/隐式销毁用例会命中既有内核缺陷导致重启）。
- **不执行的操作**：
  - 不执行 `rmmod droid_lkm*`。模块持有不可撤销的 hook、keepalive 或 proc/ns inode，`rmmod` 不会成功或可能引发内核异常；验证 `.ko` 变更需部署后重启测试。
  - 不自动执行 `insmod`、修改 `/data/adb/*`、刷入模块或 `reboot`，相关步骤交由维护者手动执行。
  - 卡开机恢复由上游 `phDroid` 模块的 `/data/adb/phdroid/insmod` → `blocked` 机制处理，启动日志位于 `/data/adb/phdroid/phdroid.log`。
- **已知环境细节**：
  - Termux Python 3.13+ 的 `platform.release()` 返回 Android 版本号（如 `17`），获取内核版本需使用 `os.uname().release`。
  - `phDroid 2.0.x` 的 `service.sh` 无 `status` 子命令，不应以 `sh /data/adb/modules/phdroid/service.sh status` 做只读查询（会走默认加载逻辑）。

## 3. 内核与构建约束

`.ko` 编译一般放在最后一步，优先在本地完成修改与验证再推送测试。CI 仅覆盖编译与零警告检查，CI 通过不代表真机加载不会卡开机或触发运行时异常。

编写和评审内核代码时需留意以下条件：

1. **KCFI（`CONFIG_CFI_CLANG=y`）**：调用通过 kallsyms 解析的函数指针或 hook 跳板的 wrapper 需标注 `__nocfi noinline`；函数指针原型应与目标内核 `$(KDIR)/source` 声明保持一致（参数类型、宽度或 `const` 修饰符偏差在未抑制 KCFI 时会触发运行时陷阱）。
2. **AArch64 BTI（`CONFIG_ARM64_BTI_KERNEL=y`）**：经间接跳转到达的入口/wrapper 可标注 `DROID_LKM_ENTRY`（`__attribute__((target("branch-protection=bti")))`），以避免开启内核 BTI 的设备发生 BTI fault。
3. **结构体布局偏移**：OEM 内核可能改动 `task_struct`、`nsproxy`、`pid_namespace`、`ipc_namespace` 等结构体布局。`src/main/` 访问已纳入 `ds_ti.c` 管理的字段时，使用 `ds.h` 中的 `droid_lkm_layout_off()` 封装；无 BTF / 非 GKI 内核走 `src/compat/ds_layout_anchor.c` 与 `src/main/core/ds_layout_manual.h`。
4. **符号解析**：优先通过 `ds_compat_sym()` / `droid_lkm_sym()` 解析内核符号，而非直接调用 `kallrecon_klp()`。前者包含针对过滤符号（如 `_text`）的 `kallsyms_name_to_addr` 回退，以及防止命中本模块同名 shim 的 `within_module` 过滤。
5. **内核写路径**：主模块在 `src/main/core/main.c` 中默认使用 `.write = hk_write_kernel`，以兼容拒绝自建 fixmap 写入的厂商内核保护（如部分 MTK 6.1 设备）。
6. **跨内核 ABI（5.10 ~ 6.18）**：
   - 模块命名空间导入使用 `DROID_LKM_IMPORT_NS(...)`（兼容 6.18 字符串形式参数）。
   - `ns_common::ops` 赋值使用 `droid_lkm_ns_set_ops(...)`（兼容 6.18 的 `ns_type` 变化）。
   - `droid_lkm_vendor.ko` 在主线 `Makefile` 中仅对 6.6 和 6.12 构建。

## 4. 目录结构

| 路径 | 说明 |
| :--- | :--- |
| `src/main/core/` | 主模块入口 `main.c`、符号表 `ds_ksym.{h,c}`、布局表 `ds_ti.{h,c}`、能力探测 `ds_caps.c`、`/proc/droid_lkm/features` |
| `src/main/slot/` | 系统调用表 slot 替换与核心 lifecycle hook（`ds_slot.c`） |
| `src/main/pidns/` | Fake PID NS、`/proc/<pid>/ns`、`/proc/<pid>/status` NSpid 模拟 |
| `src/main/ipcns/` | IPC NS、SysV IPC、POSIX mqueue、compat32、munmap 适配（`legacy`/`mas`/`vmi`） |
| `src/native/` | Native PID NS（`DROID_LKM_NATIVE_PID=1` / `DROID_LKM_PID_BOTH=1`） |
| `src/compat/` | 共享符号/BTF/锚点层（`ds_compat.c`、`ds_layout_anchor.c`）及 OPLUS vendor 修复（`vendor/`） |
| `src/hook/` | Hook 路由抽象（`slot`/`text`/`kprobe`）与关键 hook 门禁（`ds_hook.c`） |
| `src/misc/` | 容器扩展特性（devtmpfs、fake userns、xt；主线默认未启用，开发位于 `upstream/misc`） |
| `module/`、`build.gradle` | KSU/APatch/Magisk 打包脚本与 `standard`/`native`/`both` 变体注入 |
| `webui/` | React + Vite + MDUI 管理界面 |
| `scripts/dev/` | 本地只读诊断、离线预检、静态检查与用户态回归脚本 |
| `docs/` | 设备基线（`DEVICES.md`）与内核快照（`baselines/`） |

## 5. 本地工具与常用命令

按任务需要选用对应脚本：

```bash
# 查看当前设备运行态（只读：内核配置、模块、features/status、参数、phdroid 状态与 dmesg）
sudo python3 scripts/dev/diag-device.py

# 核对源码符号/BTF 契约与当前内核，并对比历史基线（适合 OTA 后或改表后）
sudo python3 scripts/dev/preflight-kernel.py --diff-baseline docs/baselines/op13-android15-6.6.json

# 静态检查（间接入口 BTI/KCFI、动态函数指针 __nocfi、裸 kallrecon_klp、ABI、类型感知 layout 直访、shell/包装）
python3 scripts/dev/check-invariants.py --self-test
python3 scripts/dev/check-invariants.py --strict

# 宿主 + lyra 容器用户态回归测试（默认安全集；装入新版 .ko 后可追加 --stress 覆盖隐式销毁/故障注入/并发压测）
sudo python3 scripts/dev/test-runtime.py --lyra
sudo python3 scripts/dev/test-runtime.py --lyra --stress

# 对已编译出的 .ko 做 vermagic / UND 符号 / 跨模块依赖 / BTI 静态检查
sudo python3 scripts/dev/preflight-kernel.py --ko path/to/droid_lkm.ko --ko path/to/droid_lkm_vendor.ko

# 同步上游与 KMSDK 依赖
git fetch upstream
scripts/fetch-deps.sh
```
