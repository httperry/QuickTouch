# QuickTouch: Apple Silicon SEP & Touch ID Protocol Specification

[![Linux Kernel](https://img.shields.io/badge/Linux_Kernel-Asahi_Mailbox-blue.svg?logo=linux&logoColor=white)](https://asahilinux.org/)
[![Apple Silicon](https://img.shields.io/badge/Architecture-Apple_Silicon_(M1--M4)-orange.svg?logo=apple&logoColor=white)](documentation/01_Architecture_and_Mailbox_IPC.md)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20CC--BY--SA--4.0-green.svg)](#license)
[![Clean-Room](https://img.shields.io/badge/Specification-Clean--Room-brightgreen.svg)](documentation/05_Linux_Implementation_Roadmap.md)

This repository contains the publication-ready, clean-room **5-Part Protocol Specification and Linux Driver Implementation Roadmap** for the Apple Silicon Secure Enclave Processor (SEP) mailbox IPC and Touch ID (`Mesa` / `AppleSandDollar`) biometric subsystem.

---

## 5-Part Specification Suite

| Document | Title | Core Coverage |
| :--- | :--- | :--- |
| [**Doc 01**](documentation/01_Architecture_and_Mailbox_IPC.md) | **Architecture & Mailbox IPC** | ASC Mailbox V4 MMIO layout, multi-die SoC base matrix, dual-register wire format (`msg0`/`msg1`), `apple-mailbox` race prevention, 28-byte `gt_packet_t` header, master 0x00–0xFF endpoint registry. |
| [**Doc 02**](documentation/02_SEP_Boot_ROM_Sequence.md) | **SEP Boot ROM Sequence** | Physical PFN vs. DART IOVA address pivot, AMC TZ0 DRAM carveout locking, complete 10-step boot ledger, Status Check 1 & 2 assertions, post-boot handover. |
| [**Doc 03**](documentation/03_Endpoint_0xFE_Control_and_Timebase.md) | **Endpoint 0xFE Control & Timebase** | Persistent Control Channel role, SEPOS `0x0D` OS Active notification and mandatory Host `0x12` ACK (Tag `0x01`), 24.0 MHz Mach timebase synchronization, sleep/wake states, FourCC whitelist filter. |
| [**Doc 04**](documentation/04_Mesa_TouchID_Protocol_and_SPI.md) | **Mesa Touch ID Protocol & SPI** | Two-Tier Encapsulation Architecture (Tier 1 outer transport `0x54` / `gt_packet_t` vs. Tier 2 inner biometric `struct bm_cmd` with magic `0x4D42`), full SBIO and Mesa opcode tables, 5-stage initialization pipeline, P-521 ECDH key exchange, 16KB capture buffer layout (`0x65`), 8.0 MHz SPI2 protocol. |
| [**Doc 05**](documentation/05_Linux_Implementation_Roadmap.md) | **Linux Implementation Roadmap** | Clean-room compliance, `m1n1` bootloader handoff, `asahi-fwextract` firmware loading, upstream Linux Mailbox client driver, `/dev/touchid0` character device UAPI, PAM daemon integration. |

---

## Automated Verification Tool

An automated Python inspection tool is included to allow developers with access to a macOS kernelcache (`kernel.kc`) to independently verify all disassembled symbols, 128-bit FIFO register interactions, and opcode string tables:

```bash
python3 documentation/verify_kernelcache.py /path/to/kernel.kc
```

---

## Clean-Room Compliance Model

This specification was developed in strict accordance with the **Asahi Linux Clean-Room Reverse Engineering Policy**:
* **Zero Disassembly / Binary Ingestion**: No verbatim assembly dumps, binary blobs, or proprietary macOS source listings are included in driver-facing specifications.
* **Functional & Architectural Abstraction**: All hardware interactions are documented as standard ANSI/ISO C99 structs, behavioral pseudocode, state machines, and Mermaid sequence diagrams.
* **Independent Driver Authoring**: Clean-room driver authors can implement the GPL Linux kernel driver purely against these behavioral specifications.

---

## License

* **Documentation & Specifications**: Creative Commons Attribution-ShareAlike 4.0 International ([CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/))
* **Header Files & Verification Code**: MIT License / GPL-2.0-only
