# 测试设备基线档案

记录主要测试设备的内核信息、配置特征、离线预检快照与运行态观察结果，供 OTA 追新和跨设备回归对照。

## 1. OnePlus 13 (`android15-6.6`)

- **设备**：OnePlus PJZ110（`OP5D0DL1`），Qualcomm SM8750
- **系统（2026-11-24）**：Android 17（`first_api_level=35`，安全补丁 `2026-11-01`）
- **内核记录**：
  - 早期记录：`6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`
  - 当前（OTA 后）：`6.6.118-android15-8-gb1422e39c313-abogki552867473-4k`
- **内核配置摘要（`/proc/config.gz`）**：
  - 未启用特性：`CONFIG_SYSVIPC=n`、`CONFIG_POSIX_MQUEUE=n`、`CONFIG_PID_NS=n`、`CONFIG_USER_NS=n`、`CONFIG_DEVTMPFS=n`
  - 构建与调试：`CONFIG_CFI_CLANG=y`、`CONFIG_CFI_PERMISSIVE=n`、`CONFIG_ARM64_BTI_KERNEL=n`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_KALLSYMS_ALL=y`、`CONFIG_KPROBES=y`、`CONFIG_TRIM_UNUSED_KSYMS=y`、`CONFIG_COMPAT=y`
- **厂商相关特征**：
  - 使用 `droid_lkm_vendor.ko`（`ghost=1 ghost_match=oplus_`）。
  - `ddl_sdata` 与 `update_ddl_hit_history` 位于模块 `[oplus_bsp_sched_assist]`，不在核心 vmlinux 中。
  - `_text` 会被内核 `kallsyms_lookup_name` 过滤，需依赖 `ds_compat_sym()` 的 `kallsyms_name_to_addr` 回退。
  - 实测 BTF `sizeof(struct task_struct) = 4800`（大于标准 GKI 头编译期尺寸，vendor 模块构造 ghost task 时不可假设编译期大小足够）。
- **崩溃 / Panic 日志路径（只读）**：
  - `/data/persist_log/backup/SYSTEM_LAST_KMSG.txt`：上次异常重启的完整内核 kmsg 与堆栈。
  - `/data/persist_log/criticallog/persist/critical.log`：`<kernel-panic-begin>` 摘要与时间记录。
  - `/data/persist_log/DCS/minidump/`：`device.info` 与 `minidump.bin`。
  - `/data/vendor/ramdump/`、`/data/vendor/olog/`：厂商 dump 目录（本机不存在 `/data/vendor/diag/`，部分其他机型可能位于 `/data/vendor/diag/` 或 `/sys/fs/pstore/`）。
- **离线预检基线**：
  - 快照文件：[baselines/op13-android15-6.6.json](baselines/op13-android15-6.6.json)
  - 2026-11-24 记录：`required_main` 5/5、`text_patch` 5/5、BTF 字段 63/63（与 `/proc/droid_lkm/features` 一致，`sizeof(upid)=16`、`sizeof(pid_namespace)=136`、`sizeof(ipc_ids)=272`）。
- **容器测试环境**：
  - `ssh lyra`：Droidspaces Debian 14 容器（`uid=1000(lyra)`），可用工具含 `gcc`、`make`、`python3`、`bwrap`、`strace`、`readelf`、`objdump`。
- **运行态观察记录**：
  - `bwrap --unshare-all` 在容器内保持普通 UID 运行正常；在 fake userns（无内核物理双层 `kuid_t` 映射）环境下，rootless podman 调用 `setresuid(0, 0, 0)` 后会修改底层 `fsuid` 为 0，在操作属主为 1000 的目录时因 `inode_owner_or_capable` 校验失败返回 `EPERM`。
  - 2026-11-24 在设备上当前运行的 `phDroid 2.0.0`（含 `droid_lkm_misc`，尚未追新至 v2.0.3）环境下：
    - 观察到 `bwrap` 退出路径 `release_task -> dec_rlimit_ucounts` 触发了一次 `WARNING at kernel/ucount.c:286`。
    - 在私有 IPC NS 内创建 POSIX mqueue 后不调用 `mq_unlink` 直接退出，在 `SYSTEM_LAST_KMSG.txt` 中实证复现 `VFS: Busy inodes after unmount of mqueue` → `kernel BUG at fs/super.c:703!`（根因：`droid_lkm_mq_kill_sb()` 仅调用 `kill_anon_super()` 漏掉 `kill_litter_super()` / `d_genocide()`；已在当前分支源码修复，测试老版本 LKM 时避免开启 `test-runtime.py --stress`）。

常用核对与更新命令：

```bash
sudo python3 scripts/dev/diag-device.py
sudo python3 scripts/dev/preflight-kernel.py --diff-baseline docs/baselines/op13-android15-6.6.json
sudo python3 scripts/dev/test-runtime.py --lyra

# 确认新内核状态后更新基线
sudo python3 scripts/dev/preflight-kernel.py --save-baseline docs/baselines/op13-android15-6.6.json
```

## 2. 一加平板 Pro (`android14-6.1`)

> 基线尚未采集，首次在设备上运行预检后补充具体数据。

- **设备**：一加平板 Pro（具体型号、内核版本与 `/proc/config.gz` 摘要待采集）
- **版本相关差异（6.1 相对 6.6）**：
  - `munmap` 适配路径对应 `do_mas_munmap`（`munmap_mas.c`），而非 6.6 的 `do_vmi_munmap`。
  - 主线 `Makefile` 当前仅对 6.6 和 6.12 构建 `droid_lkm_vendor.ko`。
- **预留基线路径**：`docs/baselines/oneplus-pad-pro-android14-6.1.json`

首次采集命令：

```bash
sudo python3 scripts/dev/diag-device.py
sudo python3 scripts/dev/preflight-kernel.py --save-baseline docs/baselines/oneplus-pad-pro-android14-6.1.json
sudo python3 scripts/dev/test-runtime.py
```
