# Adversary findings as mechanical checks

The QEMU checks include native probes derived from the adversarial Windows report generated on 2026-10-16 at 18:29. Run `vm-detector.exe --check QEMU` with stdin closed for unattended use. The probes collect data from Windows APIs and do not run PowerShell, install drivers, change firmware, or send network probes.

## Results distinguish evidence from failed measurement

The user selected this policy on 2026-10-16. BAD requires an explicit virtualization implementation identity or a specification-supported contradiction. Reproducible clues remain observations. A failed required query is ERROR. Inapplicable checks produce no report row and do not enter the totals. ERROR replaced the initially proposed SKIP because a failed measurement must remain visible, while an irrelevant test should disappear.

- `GOOD`: the named predicate was evaluated and did not match. This does not certify physical hardware.
- `BAD`: an explicit implementation identifier matched, or validated data contradicts an applicable specification requirement. There are no new scored timing thresholds or hardware-profile guesses.
- `OBS`: a measured profile, inconsistency or historical record matched. Observations do not increment failed checks.
- `ERROR`: access failed, a driver returned malformed data, or a bounded scan could not complete. Errors do not increment passed or failed checks.

This policy applies to the new adversary probes. Existing al-khaser checks retain their behavior, including older heuristics and boolean error handling. The expanded totals list observations and errors separately. Historical QEMU log entries remain observations because an image can move between machines.

## Coverage of the 48 VM findings

Every finding has one disposition in [the mechanically checked coverage file](../tests/adversary-coverage.json). Eleven report findings map to strict checks, 32 to observations, and five are not promoted. Related findings share a check; these numbers do not represent 48 independent detections. LAB and TOOL findings remain outside these VM probes.

| Finding | Treatment | Criterion or limit |
|---|---|---|
| VM-001 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-002 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-003 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-004 | observation | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-005 | observation | EDK II identity in Windows SystemBiosVersion only; raw SMBIOS does not contain that Windows-derived string. Legacy SMBIOS versions and characteristics are not independent proof. |
| VM-006 | observation | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-007 | observation | The Intel NIC is a physical product. Reported only as an observation. |
| VM-008 | observation | The NEC controller is a physical product. Reported only as an observation. |
| VM-009 | observation | Requires the four distinct resource names, not four copies of one name. |
| VM-010 | observation | Measures whole-device length. Namespace configuration can legitimately reduce capacity on physical NVMe devices. |
| VM-011 | strict | Shares one strict subsystem-ID check with VM-003. |
| VM-012 | observation | Covered with VM-004 by AMD CPU plus Q35/ICH9 identities; missing optional AMD peripherals alone is not a failure. |
| VM-013 | observation | Manufacturer mismatch is an observation; firmware can be modified. |
| VM-014 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-015 | observation | Handle numbering is a heuristic, not a requirement of the SMBIOS specification. |
| VM-016 | observation | Generic or incomplete populated-RAM inventory is an observation. |
| VM-017 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-018 | observation | Table count and EDK2 headers are observations; EDK2 also runs physically. |
| VM-019 | observation | Identifies a narrow legacy-cache profile, without assuming all Ryzen models have identical cache. |
| VM-020 | observation | Requires AMD SVM support before reading ASIDs. The count is a profile, not a universal silicon invariant. |
| VM-021 | observation | Requires bits 26, 27 and 31 together. Physical strix reports EDX=0x10000110, so the report's assertion that AMD never sets bit 28 is false. This remains an observation. |
| VM-022 | observation | Requires the exact sparse combination; firmware and microcode affect power features. |
| VM-023 | not promoted | The empty timing bracket is not a physical CPUID baseline. Existing TIMING_ATTACKS probes remain, but this report does not establish a new universal median threshold. |
| VM-024 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-025 | observation | Matches temperature 323 K with zero spare and spare threshold. Power counters can increase. A single reading does not establish constant temperature. |
| VM-026 | observation | Compares Identify with the active firmware slot, not an arbitrary stored revision. Remains observational. |
| VM-027 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-028 | observation | BootManagerMenuApp name only. Disabled Secure Boot or missing PK does not imply virtualization. |
| VM-029 | observation | Reads cached ARP/neighbour entries for default routes. Sends no packets. Prefix and subnet alone do not prove this computer is virtual. |
| VM-030 | not promoted | An invariant timestamp counter normally has a constant rate on physical CPUs. No generic clock-rate VM predicate follows from this measurement. |
| VM-031 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-032 | observation | Exact stock-OVMF language list is a profile, not proof. |
| VM-033 | observation | Exact HPET block identity is a profile. No unsupported assertion about all AMD timers. |
| VM-034 | observation | Checks SMBIOS type-19 inventory only, not the actual physical RAM map. |
| VM-035 | observation | Reads a structured processor-power event from this boot, not translated message text. |
| VM-036 | observation | Parses MADT subtables with bounds and length checks. Pattern is observational. |
| VM-037 | observation | Compares single-processor, single-L3 inventory with AMD CPUID. Disagreement can also reflect firmware bugs. |
| VM-038 | observation | Inventory versus present HDAUDIO devices; disabled hardware remains a possible explanation. |
| VM-039 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-040 | observation | Parses the current TCG2 event log. ACPI DATA measurements are an OVMF-associated observation, not exclusive VM proof. |
| VM-041 | observation | Checks Windows PCI device classification. Does not infer a physical link speed from missing properties. |
| VM-042 | not promoted | Browser discovery traffic identifies a network participant, not virtualization of this computer. The gateway observation VM-029 retains the useful network diagnostic without a timed packet capture. |
| VM-043 | strict | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-044 | not promoted | An option-ROM device path and byte length do not identify its code as iPXE. iPXE can also run on physical hardware. |
| VM-045 | observation | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-046 | observation | Reads only vendor/product fields from the Storport provider. Historical evidence stays observational. |
| VM-047 | observation | Explicit implementation identity; see primary references in docs/adversary-checks.md. |
| VM-048 | not promoted | A version-4 UUID is valid on physical hardware and need not encode a MAC. No VM predicate follows from its UUID version. |

## Why these identifiers are scored

- QEMU documents its [PCI subsystem ID 1af4:1100](https://www.qemu.org/docs/master/specs/pci-ids.html) and [standard VGA identity 1234:1111](https://www.qemu.org/docs/master/specs/standard-vga.html). Device checks use present device instance IDs, not arbitrary registry text or process command lines.
- QEMU's [firmware-configuration specification](https://www.qemu.org/docs/master/specs/fw_cfg.html) identifies `QEMU0002`. The ACPI check validates the table length and checksum before inspecting the executable DSDT/SSDT contents. The collector explicitly requests DSDT even when Windows omits it from enumeration. Repeated table signatures produce ERROR because Windows exposes only the first table per signature. It does not parse the entire AML language or establish that every matching string is an active device declaration.
- QEMU's [NVMe controller implementation](https://github.com/qemu/qemu/blob/master/hw/nvme/ctrl.c) writes `nqn.2019-08.org.qemu:`. Only the bounded SUBNQN field is matched. [Microsoft's NVMe query contract](https://learn.microsoft.com/en-us/windows/win32/fileio/working-with-nvme-devices) defines the descriptor and the relative payload offset; the parser checks both returned byte counts and lengths.
- [QEMU's AMD CPU documentation](https://www.qemu.org/docs/master/system/qemu-cpu-models.html#important-cpu-features-for-amd-x86-hosts) says `virt-ssbd` is a virtual feature absent from physical CPUs. The check requires AuthenticAMD and the supported extended leaf before testing bit 25 of 0x80000008 EBX. ASID counts and other feature combinations remain observations.
- [OVMF's QemuBootOrderLib](https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/QemuBootOrderLib/QemuBootOrderLib.c) creates `VMMBootOrder%04x`; its namespace GUID is defined in [OvmfPkg.dec](https://github.com/tianocore/edk2/blob/master/OvmfPkg/OvmfPkg.dec). The probe checks index 0000. Absence at this index does not establish that every possible numbered variable is absent. It restores the previous firmware-variable privilege after reading.
- [swtpm](https://github.com/stefanberger/swtpm) and its [local certificate authority](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm_setup.pod) identify the software TPM. IBM alone is not a failure. The TPM command requests public manufacturer/vendor properties only. Certificate reads enumerate public RSA/ECC EK certificate stores as in [Microsoft PCPTool](https://github.com/microsoft/TSS.MSR/blob/main/PCPTool.v11/exe/SDKSample.cpp), never owner authorization or private key material. The check recognizes issuer identity; it does not authenticate the certificate chain.
- The SMBIOS processor-version check recognizes the QEMU machine-version syntax `pc-q35-N.N` or `pc-i440fx-N.N`, including a possible patch version. It reads the processor-version field rather than substring-scanning the whole firmware buffer. This is an implementation identity, not a claim that the SMBIOS specification forbids arbitrary version text.

Identifiers can be changed or forged. These predicates recognize observed implementation identities; they are not a mathematical proof of virtualization against an adversary controlling every response. Hardware-profile mismatches remain observations. The later NVMe check scores a required-field contradiction under the agreed policy. A physical firmware bug could violate the same requirement; BAD is evidence of the named contradiction, not exclusive proof of virtualization.

Matched rows print evidence. GOOD rows do not print the evidence text of an unmatched predicate.

## Verification

`bash scripts/test-adversary.sh` builds the production parsers and predicates natively with AddressSanitizer and UndefinedBehaviorSanitizer. Tests replay captured firmware and NVMe bytes, alter individual identifying fields, reject close but different device IDs, exercise truncated and malformed inputs, and check that observations/errors cannot enter the failed-check count. Fixture sizes and SHA-256 hashes are checked against their collection manifest. The fixture records identify their original guest paths; generated controls are test code, not claimed physical captures.

The coverage check proves that VM-001 through VM-048 are each accounted for and that every promoted finding has an implementation. It does not prove absence of false positives on every physical PC. No bare-metal Windows control has been run.

Verified on 2026-10-16:

- The native ASan/UBSan suite passed 15,927 assertions. The manifest verified seven captured fixtures, and the coverage check accounted for all 48 VM findings.
- The complete Windows x64 binary cross-built with clang-cl using host CPU optimization and ThinLTO. Existing upstream warnings remain. MSBuild and x86 builds were not run.
- `--check QEMU` ran as SYSTEM in the adversary guest. The [captured output](verification/2026-10-16-adversary-qemu.txt) contains 10 BAD, 31 OBS, 10 legacy GOOD and zero ERROR rows. An independent parser counted the rows, checked the printed totals, and confirmed every promoted finding appeared. Related IDs share rows.
- The host and guest executable SHA-256 matched `a81f422eb2ef9d46716655fcc24a151122075f11c6e528f281f44eab3d8fef5b`.
- The Linux physical-host CPU control produced six GOOD results and no BAD/OBS/ERROR. Its extended-leaf EBX was `0x791ef257`; the guest returned `0x531ad205`. The host's leaf 7 EDX was `0x10000110`, which disproves the original report's assertion that bit 28 is Intel-only. A regression test uses that measured counterexample.
- Temporary verification tasks and the temporary Defender exclusion were removed after the run. The verification files remain in `C:\adversary\work\vm-detector-verification-4307f1bd59`.

To repeat the host CPU control on strix:

```sh
g++ -std=c++17 -O3 -march=native -mtune=native -flto tests/host_cpu_control.cpp vm-detector/AntiVM/Adversary.cpp -o /tmp/vm-detector-host-cpu-control
/tmp/vm-detector-host-cpu-control
```

## Latest Claude and Codex passes, 2026-10-17

The [latest coverage file](../tests/adversary-latest-coverage.json) accounts for every record from Claude's `claude-opus-5-5-20261017-1753` and Codex's `gpt-6.1-sol-20261017-2011`: 17 + 4 VM findings and 12 lab/tooling records. Original IDs overlap between passes, so `OPUS-*` and `CODEX-*` identify new predicates; old `VM-*` IDs retain their 2026-10-16 meanings. Related report findings can share predicates and one report finding can include both a strict identifier and observational clues.

| Source finding | Treatment | Mechanical checks |
| --- | --- | --- |
| opus vm-001 | observation | `VM-005` |
| opus vm-002 | observation | `VM-009`, `CODEX-003` |
| opus vm-003 | observation | `VM-004/012` |
| opus vm-004 | strict | `VM-002` |
| opus vm-005 | observation | `VM-010` |
| opus vm-006 | observation | `VM-022`, `OPUS-006` |
| opus vm-007 | not promoted | No new timing threshold |
| opus vm-008 | observation | `OPUS-008` |
| opus vm-009 | observation | `OPUS-009` |
| opus vm-010 | observation | `OPUS-010` |
| opus vm-011 | observation | `VM-029` |
| opus vm-012 | observation | `VM-007`, `VM-008` |
| opus vm-013 | observation | `OPUS-013` |
| opus vm-014 | partial | `VM-045`, `VM-025` |
| opus vm-015 | observation | `OPUS-015` |
| opus vm-016 | observation | `OPUS-016` |
| opus vm-017 | observation | `OPUS-017` |
| codex VM-001 | strict | `VM-002` |
| codex VM-002 | strict and observation | `CODEX-002-CAP`, `CODEX-002-OUI`, `VM-010`, `VM-024` |
| codex VM-003 | observation | `CODEX-003` |
| codex VM-004 | strict | `CODEX-004` |

LAB and TOOLING records produce no new check rows or score entries. The coverage verifier reads the unchanged source finding files and rejects missing, duplicate or extra source/ID pairs. It also checks every promoted predicate against production code. This is an accounting check, not proof that every narrative claim in a report is true. The coverage file records limits, including the unpromoted blank WMI SMART fields and unsupported universal CPUID timing threshold.

### The new strict checks

`CODEX-004` enumerates present HID interfaces with SetupAPI, opens zero-access handles and queries indices 1..12 using [HidD_GetIndexedString](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidsdi/nf-hidsdi-hidd_getindexedstring). It never reads input reports. A successfully returned string equal to `QEMU` or beginning `QEMU ` triggers BAD. All matching interfaces share one BAD row, so the same shared-table leak on both mouse and keyboard does not count twice. Interface enumeration/open errors and unexpected API errors are ERROR. Unsupported or nonexistent optional indices provide no evidence and no row; a successful read of another index cannot prove the rejected index absent. Indices above 12 are outside this targeted check. Successful strings alone are inspected; stale Win32 error codes never override success. An interface exposing no readable strings produces no GOOD row. If a required query fails, an otherwise negative scan produces ERROR without GOOD; a successful explicit identifier can still be reported with the separate error.

`CODEX-002-CAP` applies only to Identify Controller version exactly `0x00010400` (NVMe 1.4) with OACS bit 3 set. It obtains namespace 1 Identify through the [Windows NVMe property API](https://learn.microsoft.com/en-us/windows/win32/fileio/working-with-nvme-devices), validates the returned buffer, LBA-format selection, block-size exponent and NSZE/NCAP/NUSE ordering, then requires NCAP > 0, thin provisioning absent and all 128 TNVMCAP bits zero for BAD. [NVMe 1.4 section 5.15.2.2, Figure 247](https://nvmexpress.org/wp-content/uploads/NVM-Express-1_4-2019.06.10-Ratified.pdf#page=180) requires the total-capacity field when namespace management is supported. Zero total capacity contradicts a usable non-thin namespace. This follows from the field's required meaning; the specification does not name this exact byte combination as a separate rule. No exact equality between namespace bytes and total physical capacity is imposed. Zero UNVMCAP is valid. Other specification versions and controllers without namespace management produce no capacity-check row. Failed required namespace queries or malformed responses produce ERROR. Namespace IDs beyond 1 are outside this targeted repro; no blanket claim about every namespace follows.

The QEMU IEEE/OUI bytes remain OBS. Samsung's model page failed DNS during the Codex pass, so no Samsung-specific physical invariant is used in BAD. The guest iasl download also failed. `CODEX-003` checks bounded byte templates in validated AML tables and remains OBS; it is not a general AML interpreter or a live I/O protocol query. Independent host disassembly supports the captured templates.

### New observations and their controls

The new predicates cover legacy SMBIOS version with a small inventory, one-slot memory arrays whose maximum equals installed RAM, EDK2 ACPI OEM headers, a Ryzen ACPI set lacking IVRS/CRAT/CDIT, a PS/2 keyboard/mouse pair, missing Ryzen 9600X/9700X CPB, all-zero memory-encryption CPUID, and a bus-zero-only Ryzen PCI inventory without AMD identities. Each is OBS when matched. Physical firmware configuration, disabled devices and firmware defects remain possible explanations. An advertised maximum CPUID leaf does not require every lower feature leaf to be populated. No mandatory motherboard device list or physical ACPI table-count threshold is invented.

Native tests replay the archived controller, namespace, DSDT and both HID captures. Counterexamples change only the identifying/required field, including every byte of 128-bit TNVMCAP, namespace capability/version gates, thin provisioning, bad LBA formats and every truncated namespace prefix. ACPI checksum errors produce ERROR without a profile result. The sanitizer suite also tests table presence, modern SMBIOS version, larger memory-array maximum, second PCI bus and the deployed CPU fixes. The manifest verifies exact archived sizes and SHA-256 values; synthetic controls remain code, not claimed physical captures.

### Verification on 2026-10-17

The ASan/UBSan suite passed 26,390 assertions. Both fixture manifests and the original/latest coverage checks passed. The final Windows x64 binary cross-built with clang-cl, host CPU optimization and ThinLTO; MSBuild and x86 were not run. Existing upstream compiler warnings remain.

Live verification ran `--check QEMU` as SYSTEM inside the unchanged, already-running `adversary`. The [captured output](verification/2026-10-17-adversary-latest-qemu.txt) has 34 GOOD, 4 BAD, 25 OBS and zero ERROR rows. An independent parser counted every result row and matched the printed totals. BAD results are retained standard VGA, retained old swtpm EK issuer, the newly measured NVMe capacity contradiction and one shared HID identifier result covering both devices. Host and guest executable SHA-256 matched `22f23814295c1f858c2e61d0e1c6c17eb19568031610ff3f34cf5ed91152857f`. The task exited 0; the temporary scheduled task and Defender exclusion were removed. No VM restart occurred.

Dedicated GOOD rows confirm that the deployed firmware/CPU fixes cleared EDK2 OEM headers, the legacy SMBIOS entry point, missing CPB and the all-zero SME leaf. The physical Linux host CPU control returned seven GOOD results with zero BAD/OBS/ERROR; it now actually collects leaf 0x8000001f before evaluating that new predicate. No bare-metal Windows control has run. The QEMU HID patch is verified separately in stealth-vm; this adversary run is the pre-HID-fix measurement.

The HID fix was then tested on a separate `tell-fix-check` boot with QEMU `/nix/store/0h44zwg116nq031vc1srrk440f8y8v19-qemu-quiet-11.1.1`. The unchanged Codex `HidReadV2.exe` probe successfully returned an empty indexed string at index 3 on both devices, with the manufacturer/product/configuration strings and HID capabilities intact. The [fixed-guest detector output](verification/2026-10-17-hid-fixed-qemu.txt) has 35 GOOD, 3 BAD, 25 OBS and zero ERROR rows; `CODEX-004` is GOOD. VGA, old EK issuer and NVMe capacity remain BAD. This is a separate VM with the same hardware profile, not a claim that adversary was restarted or that a bare-metal control passed. Both probe/executable hashes match their host copies. Independent screenshots show the SPICE desktop and Start opening after a Windows-key event. The test VM was returned to shut off; adversary's QEMU PID and start time stayed unchanged.

The actual fixed capture is included as `hid-fixed.txt` with its own `tell-fix-check` provenance in the fixture manifest. Replaying it through production evaluation produces GOOD, while both original captures still produce one BAD. The final sanitizer run including that control passed 26,390 assertions. Git attributes preserve all fixture and captured-log bytes; staged Git blobs were checked against the fixture hashes so CRLF normalization cannot invalidate later replay.

Adversary then cold-started on the verified HID-fixed build at 00:04:42 CEST on 2026-10-18. The [deployed-adversary output](verification/2026-10-18-adversary-deployed-qemu.txt) has 35 GOOD, 3 BAD, 25 OBS and zero ERROR rows, independently counted against the printed totals. `CODEX-004` is GOOD; the unchanged original probe returns successful empty index-3 strings for both devices. The executable SHA-256 remains `22f23814295c1f858c2e61d0e1c6c17eb19568031610ff3f34cf5ed91152857f`. The retained VGA, old EK issuer and NVMe capacity contradiction remain BAD. Both guest credential-file hashes and the TPM endorsement-key hash match their pre-shutdown readings, and temporary tasks and exclusions were absent afterward. This is live verification on the original adversary instance. The [stealth-vm deployment record](https://github.com/AlexanderReaper7/stealth-vm/blob/main/docs/adversary-fixes.md#deployment-verification-2026-10-18) includes backups, process-path proof and the hash-checked archive.

The OUI-only QEMU source fix was then checked without booting Windows or activating it on the host. `tests/fixtures/nvme-oui-2026-10-18` contains actual qtest Controller and Namespace Identify responses for the corrected Samsung identity and the preserved Intel selector. Both clear `CODEX-002-OUI`; `CODEX-002-CAP` remains BAD in both, so the OUI fix cannot conceal the independent capacity contradiction. The fixture manifest records the exact QEMU derivation, patch digest, payload sizes and hashes. The native ASan/UBSan suite now passes 26,404 assertions. Production detector code and scoring are unchanged.


The fixed-namespace QEMU build was then cold-booted on `tell-fix-check` without deploying it to the host default or restarting `adversary`. The unchanged Windows detector ran as SYSTEM and returned [36 GOOD, 2 BAD, 24 observations and zero errors](verification/2026-10-18-nvme-fixed-namespace-qemu.txt). Independently counted rows match the printed totals. `CODEX-002-OUI` is GOOD; `CODEX-002-CAP` emits no row because OACS bit 3 is clear. VGA and the old swtpm EK issuer remain BAD. The executable hash remains `22f23814295c1f858c2e61d0e1c6c17eb19568031610ff3f34cf5ed91152857f`. Temporary tasks and the Defender exclusion were absent afterward, and the test VM shut down.

`tests/fixtures/nvme-fixed-namespace-2026-10-18` contains actual qtest and Windows Controller/Namespace Identify pairs, with separate provenance and exact hashes. Both report OACS `0x0123`, NN=1, actual total/namespace bytes and zero unallocated capacity. Production predicates omit the capacity row for both. Mutations that restore OACS bit 3 with zero total capacity reproduce BAD. The ASan/UBSan suite now passes 26,422 assertions. Production detector code, Windows binary and scoring are unchanged. The [stealth-vm verification record](https://github.com/AlexanderReaper7/stealth-vm/blob/main/docs/adversary-fixes.md#fixed-boot-namespace-2026-10-18) includes command rejection, real I/O, formatting and default-mode preservation tests; no destructive command ran against the Windows disk.
