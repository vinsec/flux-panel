# Local queue tuple restoration

`local_restore.o` is a checked-in little-endian CO-RE object embedded in the
Agent. It is architecture-independent across the shipped Linux amd64/arm64
builds. There is no runtime compiler, remote object download, pinned map or
userspace business-data proxy.

Build with LLVM 19 (the validation VM used Debian's signed-index packages):

```sh
clang-19 -target bpf -O2 -g -fdebug-prefix-map="$PWD"=/src -nostdinc \
  -c local_restore.c -o local_restore.o
```

Record both source and object SHA256 after compiling. This repository's object
was built with the source at `/home/fluxlab/local_restore.c`, mapped to `/src`.
Use the same basename/path mapping to reproduce its debug information.

The tc mirred/IFB path resets nfct. A post-NAT loopback packet can no longer
be matched by its translated tuple in that direction. Before redirect, this
classifier looks up the **inverted translated tuple**, verifies the business
connmark, reads the corresponding original/reply pre-NAT tuple, releases the
reference, and restores addresses/ports with IPv4 and TCP/UDP checksums. Normal
loopback RX then reattaches the same entry and repeats its existing NAT.
It does not allocate or mutate conntrack entries and does not choose targets.

The 12-byte default-zone lookup ABI is intentional. Linux 6.1 requires 12;
Linux 6.12 accepts 12 and 16. Passing 16 to an older kernel can load successfully
but make every lookup fail. See the primary implementation in
[Linux 6.1](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nf_conntrack_bpf.c)
and [Linux 6.12](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_conntrack_bpf.c).

A missing/mismatched conntrack entry drops the queued data packet. ICMP control
bypasses this queue in tc. Local shaping requires loopback MTU >= 131072, keeping
ordinary maximum-size IPv4/IPv6 UDP datagrams complete before queueing. Physical
ingress is defragmented by the tc ct action. Locally injected raw noninitial
fragments, IPv6 routing/AH and jumbograms are outside this optional queue contract.
Base forwarding without local shaping retains its existing packet handling.

The agent loads this exact object first on an unconnected, down owned IFB probe.
Kernel/BTF/libbpf/permission failures close desired locally limited rules before
installing their active generation. The optional helper profile requires CAP_SYS_ADMIN for module-BTF discovery, as well as CAP_BPF.
Administrator-prepared bpffs and its empty tc/ip/xdp globals directories let tc load a
mapless object under the documented optional capability profile and a read-only /sys mount.
