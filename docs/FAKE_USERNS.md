# Fake User Namespace (`src/misc/userns/`) 设计与维护手册

本文档记录 `droid_lkm_misc.ko` 中模拟用户命名空间（fake userns）的架构边界、核心不变量、对象生命周期矩阵、安全红线与维护检查清单，供后续迭代与排错查阅。

---

## 1. 设计定位与明确边界

Android GKI 内核默认关闭 `CONFIG_USER_NS=n`，导致内核在编译期将：
- 所有 `get_user_ns()` / `put_user_ns()` 展开为空桩（不维护引用计数）；
- 所有 `make_kuid()` / `make_kgid()` / `from_kuid()` / `from_kgid()` 展开为恒等映射（忽略 `uid_map` / `gid_map`）；
- 所有 `current_user_ns()` 展开为硬编码 `&init_user_ns`。

因此 LKM 模拟层存在**明确的物理能力上限**：

| 场景 | 是否支持 | 说明 |
| :--- | :---: | :--- |
| `bwrap --unshare-all` / 沙箱隔离 | **支持** | 写 `setgroups=deny` + 单条自映射 `uid_map`/`gid_map`，隔离 `user`/`pid`/`ipc`/`mnt`/`net`/`uts`/`cgroup`，挂载 `proc`/`tmpfs`/`ro-bind`，随后 `capset(0)` 丢弃权限。 |
| Chromium / Electron userns 沙箱 | **支持** | 同上，创建单映射 userns + pidns + netns 后即丢弃能力并启用 seccomp。 |
| Droidspaces `user-ns` 运行态检测与基础容器 | **支持** | 含 `/proc/<pid>/ns/user`、`NS_GET_USERNS`、`uid_map`/`gid_map`/`setgroups` 状态机、特权容器 `chown_common` 映射。 |
| Rootless Podman / Buildah / 多 UID 发行版容器 | **不支持** | 依赖全内核 `make_kuid()`/`from_kuid()` 翻译与 `subuid` 65536 段多 UID 切换，`CONFIG_USER_NS=n` 下无法由 LKM 安全实现。 |
| 面向恶意本地 App 的多租户安全沙箱 | **不支持** | 仅定位为单用户受控设备上的容器/沙箱兼容层；不能替代内核开启 `CONFIG_USER_NS=y`。 |

> **运维退路**：若某设备完全不需要 `CLONE_NEWUSER` 兼容，可直接在模块参数中设置 `droid_lkm_misc` 的 `userns=0`（仍保留 `devtmpfs` 与 `xt`），零攻击面、无需重编内核模块。

---

## 2. 模块组成与代码地图

| 文件 | 职责 |
| :--- | :--- |
| `src/misc/userns/userns_core.c` | `struct droid_lkm_userns` 分配、全局列表（上限 `1024`）、`get`/`put` 引用计数、RCU + workqueue 异步销毁、模块驻留（`stay_resident`）与初始化编排。 |
| `src/misc/userns/userns_lsm.c` | **首选** cred 生命周期记账：读取运行时 BTF 布局，经私有 `vmap` + `stop_machine()` 向 `security_hook_heads` 挂载 `cred_prepare` / `cred_free` / `cred_transfer`（5.10–6.6 有 BTF 时生效，6.12+ 或无 BTF 自动回退 `ds_hook`）。 |
| `src/misc/userns/userns_cred.c` | `cred->user_ns` 切换、受限 userns 能力裁剪（剥离 `CAP_SETUID`/`CAP_SETGID`）、fail-closed 剥权、`unshare` 失败时的 `prepare_creds()` 安全回滚。 |
| `src/misc/userns/userns_hooks.c` | 核心闸门与入口：`security_capable`、`capable_wrt_inode_uidgid`、`mount_capable`、`unshare_nsproxy_namespaces`、`inc_ucount`/`alloc_ucounts`/`set_cred_ucounts`、`chown_common`（回退 `fchownat`+`fchown`）、`copy_creds`、`ksys_unshare`，以及无 LSM 时的 cred hook 回退。 |
| `src/misc/userns/userns_owner.c` | 内核私有/受管 namespace 的属主与配对引用计数：`mnt_ns`（`put_mnt_ns` + `mntns_operations.put` 幂等双守门）、`uts_ns`、`net_ns`（原生 `register_pernet_subsys`）、`cgroup_ns`、`time_ns`，以及 `fs_context_for_mount`。 |
| `src/misc/userns/userns_nsops.c` | `/proc/<pid>/ns/user` 的 `proc_ns_operations`，向 `droid_lkm.ko` 注册 `user` namespace 类型及跨模块 `get_user_ns`/`put_user_ns` 回调。 |
| `src/misc/userns/userns_proc.c` | `/proc/<pid>/{uid_map,gid_map,setgroups}` 实现（通过直接替换 `proc_t{g,}id_base_inode_operations.lookup` 槽位挂载）。 |
| `src/misc/userns/userns_map.c` | 映射表解析、单向写锁、祖先链校验与内建域测试。 |
| `src/misc/misc_layout.{h,c}` | 运行时 BTF 偏移验证（含 `*_ok` 标志区分合法偏移 `0`，如 `mnt_namespace.ns` 与 `time_namespace.user_ns`）。 |
| `src/main/pidns/ds_proc.{h,c}`、`ipcns.c`、`pidns.c` | `droid_lkm.ko` 侧跨模块协作：为 `ipc_namespace` 持有/释放假 userns 引用，并在假 userns 销毁前通过 `droid_lkm_pidns_detach_user_ns()` 清理存活假 `pid_namespace` 的 `->user_ns`。 |

---

## 3. Hook 路由策略与 F3 安装顺序

### 3.1 路由分层（兼顾 6.1/6.6 热路径性能与全矩阵兼容）
- **零 trap 原生扩展点**：
  - `cred_prepare` / `cred_free` / `cred_transfer` -> BTF `security_hook_heads`（`userns_lsm.c`）
  - `/proc/<pid>` lookup -> `proc_t{g,}id_base_inode_operations.lookup` 槽位直替（`userns_proc.c`）
  - `net` 命名空间生命周期 -> 内核原生 `register_pernet_subsys`（`.init`+`.exit` 配对 0 Hook、零热路径开销、100% 免疫 LTO 内联；`.exit` 写入永生非-init 哨兵 `dead_uns` 保持 `uevent_net_init/exit` 对称）
  - `mnt` nsfs 析构 -> `mntns_operations.put`（`mntns_put` 槽位直替，兜底同文件内联）
- **高频热点（走 `ds_bhook` 单指令 4 字节 `B` 跳板，不满足时自动退回 `kprobe`）**：
  - `security_capable`、`capable_wrt_inode_uidgid`、`set_cred_ucounts`、`copy_creds`
- **低频冷路径（`kprobe`，零热路径负担）**：
  - `mount_capable`、`unshare_nsproxy_namespaces`、`chown_common`、`inc_ucount`、`alloc_ucounts`、`ksys_unshare`
  - namespace 属主配对：`copy_mnt_ns`/`put_mnt_ns`、`copy_utsname`/`free_uts_ns`、`copy_cgroup_ns`/`free_cgroup_ns`、`copy_time_ns`/`free_time_ns`、`fs_context_for_mount`（`net` 完全走原生 `pernet_operations` 无需 hook `copy_net_ns`）

### 3.2 F3 安装顺序不变量（严禁破坏）
初始化必须严格满足 **「记账/防线在前，生产者最后，且受 `droid_lkm_userns_ready` 门禁保护」**：
1. `droid_lkm_userns_nsops_init()`（向 `droid_lkm.ko` 注册 `user` 种类与跨模块引用回调）
2. `droid_lkm_userns_owner_init()`（先挂所有析构回收 `put_mnt_ns`+`mntns_put`、`free_*`、`register_pernet_subsys`，再挂 `copy_*`）
3. `droid_lkm_userns_hooks_init()`：
   - Step 1：可逆防线与 `ucounts` 隔离（`security_capable`、`capable_wrt_inode_uidgid`、`mount_capable`、`unshare_nsproxy_namespaces`、`inc_ucount`、`alloc_ucounts`、`set_cred_ucounts`、`chown_common`）
   - Step 2：不可逆 LSM cred 记账（`userns_lsm_init()` 或 `ds_hook` 回退）
   - Step 3：生产者入口（`copy_creds`、`ksys_unshare`）+ `smp_wmb()` + `WRITE_ONCE(droid_lkm_userns_ready, true)`

---

## 4. 对象生命周期与引用计数矩阵（防 UAF 核心）

**铁律**：由于 `get_user_ns()` / `put_user_ns()` 是空桩，**凡是往任何内核结构体写入 `&u->uns` 的位置，必须明确回答「谁拿引用、谁在不可逆析构点归还引用」；若无法闭环，必须 fail-closed 写 `init_user_ns`。**

> **Clang ThinLTO 同文件内联教训（严禁踩坑）**：
> - 在 GKI `CONFIG_LTO_CLANG_THIN=y` 下，同编译单元内部的辅助函数（如 `fs/namespace.c` 里的 `static free_mnt_ns`、`net/core/net_namespace.c` 里的 3 行 `net_drop_ns`）即使在 `/proc/kallsyms` 中留有冷路径符号，主析构路径也已被内联进 `put_mnt_ns` / `cleanup_net`，单独 hook 它们会导致 100% 引用泄漏；跨文件的 1 行函数 `proc_free_inum` 同样未导出 `__ksymtab`，有跨文件 LTO 内联风险。
> - 析构回收必须锚定在**头文件非 inline 慢路径外部接口**（如 `free_uts_ns`/`free_cgroup_ns`/`free_time_ns`、`put_mnt_ns`）或**运行时不可内联的链表/虚表回调**（`register_pernet_subsys`、`mntns_operations.put`）。

| 内核对象 / 字段 | `get` / 持有位置 | `put` / 清理位置 | BTF / 安全性说明 |
| :--- | :--- | :--- | :--- |
| `struct cred::user_ns` | `userns_cred.c` / `userns_lsm.c` (`cred_prepare` & `cred_transfer`) | `userns_lsm.c` (`cred_free` 用 `xchg` 幂等防双释放 + F2 `cred->security == NULL` 防线) | `u->count` 归零后走 `call_rcu` + `schedule_work` 异步释放，覆盖 `put_cred_rcu` 全流程。 |
| `struct ucounts::ns` | **永不持有 `&u->uns`** | — | **核心不变量**：`inc_ucount` / `alloc_ucounts` / `set_cred_ucounts` 将假 userns 一律重定向至永生的 `init_user_ns`，一次根治异步 `cleanup_net -> dec_ucount` UAF 与 `execve -> dec_rlimit_ucounts` 下溢 `WARN_ON_ONCE`。 |
| `mnt_namespace::user_ns` | `userns_owner.c` (`copy_mnt_ns`) | `userns_owner.c` (`put_mnt_ns` + `mntns_operations.put` 双入口，`refcount_dec_not_one` + 原子 `xchg` 幂等并在 `orig()` 后 `put`) | 同时覆盖跨 TU `free_nsproxy` 与延迟关闭 `/proc/<pid>/ns/mnt` fd（防 `put_mnt_ns` 内联进 `mntns_put`）；BTF `mnt_namespace.{ns,user_ns}` 验证。 |
| `uts_namespace::user_ns` | `userns_owner.c` (`copy_utsname`) | `userns_owner.c` (`free_uts_ns`，`orig()` 之后 `put`) | 覆盖 `unshare()` 与 `clone()`；需 BTF `uts_namespace.user_ns` + 析构符号同时就绪。 |
| `net::user_ns` | `userns_owner.c` (`register_pernet_subsys` 的 `.init` 回调，内核 `setup_net()` 先写入 `net->user_ns` 再调用 `.init` 持引用) | `userns_owner.c` (`register_pernet_subsys` 的 `.exit` 回调，原子 `xchg` 写入永生非-init 哨兵 `dead_uns` 后 `put`) | 零 hook、零热路径开销、100% 免疫 LTO 内联；严禁在 `.exit` 改回 `init_user_ns`（否则 `cleanup_net` 逆序执行到 `uevent_net_exit` 会因 `net->user_ns == &init_user_ns` 误删未入链的 `ue_sk->list` 触发空指针 panic）。 |
| `cgroup_namespace::user_ns` | `userns_owner.c` (`copy_cgroup_ns`) | `userns_owner.c` (`free_cgroup_ns`，`orig()` 之后 `put`) | 覆盖 `unshare()` 与 `clone()`；BTF 校验。 |
| `time_namespace::user_ns` | `userns_owner.c` (`copy_time_ns`) | `userns_owner.c` (`free_time_ns`，`orig()` 之后 `put`) | 注意 `time_namespace.user_ns` 偏移为 `0`，须用 `_ok` 布尔判定。 |
| `ipc_namespace::user_ns` | `src/main/ipcns/ipcns.c` (`droid_lkm_userns_hold`) | `src/main/ipcns/ipcns.c` (`ds_free_ipc_ns` 调 `droid_lkm_userns_drop`) | 通过 `droid_lkm_ns_kind_reg` 跨模块回调闭环。 |
| `pid_namespace::user_ns` | `src/main/pidns/pidns.c`（不增 `u->count`，避免假 pidns 常驻导致 `u` 泄漏） | `userns_core.c` 在 `u->count == 0` 且 `call_rcu` 之前调 `droid_lkm_pidns_detach_user_ns(&u->uns)` | 将残留假 `pid_namespace->user_ns` 原子重设为 `init_user_ns`。 |
| `nsfs` `/proc/<pid>/ns/user` | `userns_nsops.c` (`nsops_get`) | `userns_nsops.c` (`nsops_put`) | 标准 nsfs 引用计数。 |
| `/proc/<pid>/{uid,gid}_map` | `userns_proc.c` (`proc_ns` / `open`) | `userns_proc.c` (`release`) | 打开文件期间持引用。 |
| `struct fs_context::user_ns` | 不单独计引用（同步 `do_new_mount` 期间借用 `current->cred` 引用） | 挂载返回即销毁 | 已知限制：不覆盖直接调 `alloc_fs_context()` 的 `fsopen()` 新挂载 API。 |
| 父子嵌套 `u->uns.parent` | `userns_core.c` (`droid_lkm_userns_create`，`got_parent` 守卫防失败双 `put`) | `userns_core.c` (`droid_lkm_userns_free_work`) | 嵌套深度上限 32。 |

---

## 5. 安全红线（绝不可退让）

1. **禁止假 userns 持有对 `init_user_ns` 的任何能力**：`droid_lkm_userns_seccap_eval()` 对 `ns == init_user_ns` 且 `cred` 位于假 userns 的请求一律返回 `-EPERM`。
2. **受限假 userns（`!u->privileged`）严禁 `CAP_SETUID` / `CAP_SETGID`（P0-1 LPE 防线）**：
   - `userns_cred.c`：对 `!u->privileged` 从 `cap_{inheritable,permitted,effective,ambient,bset}` 全部剥离 `CAP_SETUID` 和 `CAP_SETGID`；
   - `userns_hooks.c`：`droid_lkm_userns_seccap_eval()` 对 `!targ_u->privileged` 硬拦截 `CAP_SETUID`/`CAP_SETGID`（连父属主规则也不可绕过，仅宿主 root 或特权祖先放行）。
   - 原因：`make_kuid()`/`make_kgid()` 在 `CONFIG_USER_NS=n` 下退化为恒等映射，若放行这两个能力，非特权进程调 `setresuid(0)` / `setfsuid(0)` / `setresgid(42)` 会直接改写全局内核 UID/GID 并穿透 VFS DAC 与 `kill()` 权限检查。
3. **引用失败必须 fail-closed**：`droid_lkm_userns_cred_fail_closed()` 在把 `user_ns` 退回 `init_user_ns` 前必须先清空全部 5 组 capability 集合（F1-a/F1-b）。
4. **`unshare` 失败回滚必须分配新 cred**：通过 `droid_lkm_userns_rollback_current()` 走 `prepare_creds()` 构造 `subscribers == 0` 的未提交凭证再 `commit_creds()`，严禁把 `get_task_cred()` 返回的共享只读凭证强转给 `commit_creds()`。
5. **模块驻留不可撤销**：一旦注册 `proc_ns_operations` 或向 `security_hook_heads` 挂载不可逆 LSM 节点，即通过 `try_module_get(THIS_MODULE)` 锁定驻留（`rmmod` 必须返回 `-EBUSY`）。

---

## 6. 维护与回归检查清单

每次修改 `src/misc/userns/` 或 `src/misc/misc_layout.*` 后，按顺序完成以下验证：

```bash
# 1. 静态不变量门禁（BTI / KCFI / __nocfi / 结构体直访 / ABI）
python3 scripts/dev/check-invariants.py --self-test
python3 scripts/dev/check-invariants.py --strict --include-misc

# 2. CI 编译全矩阵零警告检查（5.10 ~ 6.18 standard / native / both）
#    重点确认 5.15 / 6.1 / 6.6 / 6.12 上 droid_lkm_misc.ko 零警告

# 3. 刷入重启后核查运行态表面
sudo python3 scripts/dev/diag-device.py
#    核对 /proc/droid_lkm_misc/status:
#      - userns cred lsm   : ready (security_hook_heads ...)
#      - userns ucounts    : ready (init_user_ns (inc+alloc+setcred))
#      - userns mount owner: ready (field verified via Type_info (put_mnt_ns+mntns_put))
#      - userns ns owners  : ready (mnt ipc uts net cgroup time)
#      - userns objects    : ready (0 live of 1024)

# 4. 宿主 + lyra 全套功能、安全（含 userns_lpe_guard）与压测
sudo python3 scripts/dev/test-runtime.py --lyra --stress
```
