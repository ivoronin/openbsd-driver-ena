# openbsd-driver-ena

A from-scratch ena(4) driver for OpenBSD: the Amazon Elastic Network
Adapter, which is the only NIC that modern EC2 instance types expose.
Stock OpenBSD has no ENA driver, so on current instance families it
boots with no network at all. This driver closes that gap. It is
written against the ENA ABI published in
[amzn-drivers](https://github.com/amzn/amzn-drivers), with the ena-com
layer and the FreeBSD ena(4) driver as read-only references.

## What works

- Full control plane on real EC2 hardware: admin queue, async event
  queue, feature negotiation, keepalive watchdog, and automatic
  device reset recovery.
- The host-mode datapath.
- The LLQ datapath, used by the newer Nitro generations (Graviton3
  and later).
- Device statistics via kstat(4): per-ring and device-level software
  counters, the device's own traffic and EC2 allowance counters read
  over GET_STATS, and drop/overrun counts fed to `netstat -in`.

## What's planned

The MVP scope was deliberately narrow: one RX/TX queue pair, MTU
1500, checksums in software. The full gap to a mature ena(4) looks
like this:

- Performance: TX/RX checksum offload, multiqueue with RSS (one
  MSI-X vector per queue pair), interrupt moderation, TSO.
- Features: jumbo frames to MTU 9000, and honoring the device's
  recommended wide 256-byte LLQ entries (independent of jumbo).
- Robustness: an RX empty-ring recovery net beneath the pinned-full
  ring.
- Platforms: the OpenBSD 8.0 / -current port, including adding
  IFXF_MBUF_64BIT support.
- Not planned: suspend/resume (instance hibernation) and ENI
  hot-plug - both are niche for what this project is for.

## How to consume this work

This repository holds only the driver sources under `src/sys/`. The
consumable artifact is an EC2 image, and it is built in two stages:

- [openbsd-kernel-aws](https://github.com/ivoronin/openbsd-kernel-aws)
  builds the AWS kernel bundle: it fetches this repository at a
  pinned ref during the build, splices `src/sys/` into the OpenBSD
  source tree, applies the kernel-side glue it maintains itself
  (pcidevs entries, files.pci hookup, EC2 platform patches) and
  compiles the kernel.
- [openbsd-cloudimg](https://github.com/ivoronin/openbsd-cloudimg)
  builds ready-to-run OpenBSD AMIs on top of that kernel bundle.

So: for images go to openbsd-cloudimg, for the kernel build and the
exact patch set go to openbsd-kernel-aws, and to hack on the driver
copy `src/sys/` over an OpenBSD source tree together with the glue
patches from openbsd-kernel-aws.

## Not headed upstream

This is heavily AI-assisted code, and the OpenBSD project does not
accept AI-generated code (see the
[statement on tech@](https://marc.info/?l=openbsd-tech&m=177425035627562&w=2)).
This driver therefore stays an independent project for running
OpenBSD on EC2, not an upstream candidate.
