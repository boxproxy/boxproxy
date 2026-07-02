# boxproxy

Native components for running the **box** proxy on Android: a Rust control CLI
and an eBPF traffic matcher. They are built for `aarch64-linux-android` and ship
inside the box app / Magisk module.

## Components

The repository contains two independent, sibling components:

### boxctl

A Rust command-line tool that drives the proxy on the device. It manages the
iptables / eBPF routing rules, the core configuration, the SQLite rules
database, Wi-Fi monitoring, and the service lifecycle.

`boxctl` evolved from the shell scripts of the original
[boxproxy/box](https://github.com/boxproxy/box) project — the same logic,
reworked in Rust for speed, atomic batched iptables updates, and a single
self-contained binary with no shell dependencies.

For sing-box configurations that use remote rule sets, `boxctl` can optionally
preload those rule sets before starting the core and run sing-box with a
generated config that points to local cached files. This avoids first-start
failures caused by the sing-box process resolving or downloading rule-set URLs
before the proxy path is available.

Enable it with `--sing-rule-set-preload`, or set
`app_settings.sing_rule_set_preload=true` in `box.db`. Cached rule sets live in
`$BOX_HOME/sing-box/rule-set` by default; use `--sing-rule-set-dir PATH` or
`app_settings.sing_rule_set_preload_dir` to override the directory. Use
`--sing-rule-set-refresh` or `app_settings.sing_rule_set_preload_refresh=true`
to refresh an existing cache before start.

```sh
cd boxctl
cargo build --release --target aarch64-linux-android
```

(Set the Android NDK linker via `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER` and
the matching `CC_/CXX_/AR_aarch64_linux_android` toolchain variables.)

### boxbpf

A small C tool that assembles, loads, and pins eBPF **socket-filter** programs
for `xt_bpf` (`iptables -m bpf --object-pinned`). The pinned programs match
traffic by CIDR (v4/v6), UID, and a force-proxy direction flag driven by a
runtime-config map.

The programs are hand-assembled `bpf_insn` arrays loaded through the `bpf()`
syscall, with a direct-packet-access → `skb_load_bytes` → `BPF_LD_ABS` read-mode
fallback so they keep working across the kernels Android devices actually ship.
The matcher design references the eBPF approach in
[Asterisk4Magisk/AsteriskNG](https://github.com/Asterisk4Magisk/AsteriskNG).

```sh
cd boxbpf
make           # or: clang -O2 -fPIE -pie main.c loader.c config.c -o boxbpf
```

## License

This project is licensed under the **GNU General Public License v3.0**
(GPL-3.0-or-later). See [LICENSE](LICENSE).

## Credits and Referenced Projects

boxproxy builds upon and credits the following projects:

- **[boxproxy/box](https://github.com/boxproxy/box)** — the original shell-based
  box proxy; `boxctl` is a Rust evolution of its control logic.
- **[Asterisk4Magisk/AsteriskNG](https://github.com/Asterisk4Magisk/AsteriskNG)**
  — referenced for the eBPF `xt_bpf` socket-filter matcher approach used by
  `boxbpf`.
