# Optional kernel probes

`vm-detector.exe --check QEMU --check KERNEL` combines the existing user-mode checks with fresh kernel measurements. KERNEL is opt-in and requires the companion driver already loaded. The executable never installs a service, signs a driver, changes boot security or reads an old report. A missing/inaccessible driver produces two ERROR rows. Omitting KERNEL produces no kernel rows, including with the default selection.

The companion x64 WDM driver creates `\\.\VmDetectorKernel` with an administrator/SYSTEM DACL through [IoCreateDeviceSecure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure). Its original KERNEL operation accepts an input-free, fixed-size, buffered IOCTL. The separate network operation is described below. The caller cannot supply an MSR, port, address, payload or command. It reads six documented [KVM MSRs](https://www.kernel.org/doc/html/latest/virt/kvm/x86/msr.html) and two invalid-register controls, then a bounded [fw_cfg directory](https://www.qemu.org/docs/master/specs/fw_cfg.html). Port writes select only read items 0, 1 and 0x19; there are no data-register writes, WRMSR operations, DMA or memory-mapping requests. The selector/read cursor changes during collection. Concurrent clients serialize their port transactions through a driver mutex.

The versioned response has fixed-width fields and no pointers. The collector validates its exact size and CPL0 context. The evaluator validates every MSR index/status, both fault controls and the complete bounded firmware directory before scoring. The wire format is an internal collector protocol, not cryptographic attestation against a hostile kernel or hypervisor.

## Build

The ordinary executable build needs no WDK. The optional driver uses Microsoft WDK headers and `ntoskrnl.lib`, `hal.lib`, `wdmsec.lib` and `BufferOverflowK.lib`, with its GS-initializing entry point. The NuGet index was queried on 2026-10-19; the latest stable `Microsoft.Windows.WDK.x64` was `10.0.28000.2526`, whose headers/libraries use the `10.0.28000.0` subdirectory. The build downloads nothing automatically.

```bash
WDK_ROOT=/path/to/unpacked-wdk/c WDK_VERSION=10.0.28000.0 \
  bash scripts/build-kernel-clang-cl.sh /absolute/path/vm-detector-kernel.sys
bash scripts/build-clang-cl.sh /absolute/path/vm-detector.exe
```

The scripts use the existing clang-cl/LLVM and Windows SDK installation, native CPU optimization and LTO. `WDK_ROOT`, `WDK_VERSION`, `WIN_SDK` and `LLVM_BIN` can point to other installed toolchains. The driver output is unsigned. Windows x64 driver-signing requirements still apply. [Test-signed driver loading](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) requires a deliberately configured lab and a reboot when its boot option changes; none of that occurs inside vm-detector.

After signing and arranging the required Windows signing policy, these are explicit elevated service operations:

```powershell
sc.exe create VmDetectorKernel type= kernel start= demand binPath= C:\tools\vm-detector-kernel.sys
sc.exe start VmDetectorKernel
C:\tools\vm-detector.exe --check QEMU --check KERNEL
sc.exe stop VmDetectorKernel
sc.exe delete VmDetectorKernel
```

No automatic service or security-state cleanup is implied. The executable only opens the existing device and closes its handle. The driver is demand-start and unloadable. A 32-bit detector can use the pointer-free protocol on x64 Windows, but that build has not been verified. Only the x64 companion driver is supplied as source.

## Scoring

| Finding | Check | Result policy |
| --- | --- | --- |
| VM-K01 | KVM private MSRs | BAD if any of the six named private registers succeeds and both invalid controls raise `C0000096`; GOOD if all six fault with that exception; ERROR for inconsistent indices, unexpected exceptions or inconclusive controls. |
| VM-K02 | KVM/OVMF firmware filenames | BAD for exact `genroms/kvmvapic.bin` or the `opt/ovmf/` setting namespace in a fully validated directory; GOOD when neither matches; ERROR for failed, truncated, malformed or over-limit queries. An undiscovered interface has no firmware row. |
| VM-K03 | Existing VM-002 | Standard VGA is already scored through present PCI device IDs; KERNEL adds no duplicate row. |
| VM-C01 | Customized firmware signatures | OBS for `AMIF` and `AMIF CFG` with DMA support and a validated compatible directory. It does not fail the VM score. No matching clue produces no row. |

Lab accounts, the driver's presence, signing changes, certificates and development tools are excluded from VM findings. A GOOD result clears only the named predicate; it does not prove physical hardware.

The native sanitizer tests replay the original pre-fix and fixed Windows measurements, plus a real binary response from this companion driver. Truncated replies, malformed directories, close-but-different filenames, unavailable drivers and failed controls have separate tests. [The checked coverage file](../tests/kernel-coverage.json) accounts for all six entries in the review, including lab/tooling exclusions. [Live verification](../docs/adversary-checks.md#kernel-pass-checks-2026-10-19) records driver execution and cleanup.

## Network kernel checks

Version 0.84 adds `vm-detector.exe --check NETKERNEL`. This separate opt-in sends IOCTL `0x83376004` to the same companion driver. The original KERNEL IOCTL and its version-1 response remain unchanged. Older drivers reject the new request, which produces ERROR. The new request has no input and returns an independent fixed-width 804-byte version-1 response.

The collector searches segment-zero PCI buses for one `8086:10d3` controller, reads its 256-byte configuration and maps the first 4 KiB of its already assigned, enabled 32-bit BAR0. Two measurements read EECD and the first 64 NVM words. EERD writes issue read commands only; they do not write EEPROM, reset the controller or modify PCI configuration. The original EERD address is read again afterward. Polling is bounded to 1,000 one-microsecond stalls per word. Conflicting EERD address/completion, failed reads, duplicate controllers and unstable measurements produce ERROR. The mutex serializes this driver's clients, not an unrelated vendor driver. This is a lab diagnostic, not a PnP filter attached to the vendor driver's resource stack. Secure Boot/HVCI or platform restrictions can prevent collection. No equivalent user-mode access is claimed.

Only an absent target after readable PCI enumeration omits the checks. Unavailable driver access or failed collection produces two ERROR rows. Missing/invalid NVM signature, checksum or autoload state cannot produce GOOD. An unrequested NETKERNEL produces no rows.

- `NET-VM-01` is BAD for a nonzero PCIe device type or extended-tag support on this chip. Intel specifies endpoint type zero and five-bit tags.
- `NET-VM-02` is BAD for reserved NVADDS zero with a valid NVM signature, presence and completed autoload.
- `NET-C02` reports NVM/live subsystem-ID or supported-payload mismatches as observations. A read-only snapshot cannot rule out software editing EEPROM after autoload. It never promotes those mismatches alone to BAD.
- `NET-CLUE-01` reports an exact QEMU EEPROM template match as an observation. MAC and checksum substitutions are allowed; all remaining words must match. Physical programmable NVM can contain the same bytes.

The reference is [Intel 82574 datasheet 317694-016](https://docs.rs-online.com/96e8/0900766b81384733.pdf), sections 6.2.1.4-6, 6.2.1.18, 9.1.6.1.3-4 and 10.2.2.3-4. The checks cover the documented 82574L behavior, not every possible later silicon stepping or fabricated PCI endpoint. The report's NVM mismatch and reserved address encoding share one original finding; the detector separates their different evidential strength.

The network fixture directory preserves both original Windows kernel logs. `before.bin` translates those records into the new protocol, and `fixed-*.bin` contain actual disconnected QEMU qtest measurements in that protocol. Their execution-context headers describe the protocol expected by the parser; they are not Windows companion-driver executions. Native sanitizer tests cover both immutable properties independently, reserved address mode, editable NVM controls, complete template matching, every truncated response, cyclic capability lists, checksum/signature failures, unstable samples, query failures and absent targets.

`live-20261020.bin` is the actual Windows companion-driver response after deployment. Its two samples agree and both network checks are GOOD. [Live verification](../docs/adversary-checks.md#live-network-kernel-verification-2026-10-20) records the driver load, CPL0 response, rejected malformed requests and restoration of the guest's original security settings. The targeted sanitizer replay includes this response.
