#include "KernelProbe.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>

namespace adversary {
namespace {
std::string hex(std::uint32_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
    return out.str();
}
bool identifier(const std::string& name)
{
    return name == "genroms/kvmvapic.bin" || name.rfind("opt/ovmf/", 0) == 0;
}
}

std::vector<Result> evaluate_kernel(const Sample<Bytes>& response)
{
    static_assert(sizeof(VmdKernelReply) == VMD_KERNEL_REPLY_SIZE, "kernel protocol layout");
    if (response.state == ReadState::NotApplicable) return {};
    const auto errors = [](const std::string& why) {
        return std::vector<Result>{{"VM-K01", "KVM private MSRs (kernel)", CHECK_ERROR, why},
            {"VM-K02", "KVM/OVMF firmware-directory identifiers (kernel)", CHECK_ERROR, why}};
    };
    if (response.state == ReadState::Error) return errors(response.reason);
    if (response.value.size() != sizeof(VmdKernelReply)) return errors("kernel response has the wrong size");
    VmdKernelReply reply;
    std::memcpy(&reply, response.value.data(), sizeof(reply));
    if (reply.version != VMD_KERNEL_VERSION || reply.size != sizeof(reply) ||
        !reply.cs || (reply.cs & 3) || reply.irql > 1)
        return errors("invalid kernel response version, size or execution context");
    std::vector<Result> out;
    const std::uint32_t expected[VMD_MSR_COUNT] = {
        0x4b564d00, 0x4b564d01, 0x4b564d02, 0x4b564d03,
        0x4b564d04, 0x4b564d05, 0xdeadbeef, 0xffffffff
    };
    bool valid = true;
    for (unsigned i = 0; i < VMD_MSR_COUNT; i++) {
        const auto& m = reply.msrs[i];
        if (m.index != expected[i] || (m.status != 0 && m.status != VMD_PRIVILEGED_INSTRUCTION) ||
            (i >= 6 && m.status != VMD_PRIVILEGED_INSTRUCTION)) valid = false;
    }
    if (!valid) out.push_back({"VM-K01", "KVM private MSRs (kernel)", CHECK_ERROR,
        "unexpected MSR index/status or invalid-register control did not fault"});
    else {
        std::string matches;
        for (unsigned i = 0; i < 6; i++) if (!reply.msrs[i].status) {
            if (!matches.empty()) matches += "; ";
            matches += hex(reply.msrs[i].index) + "=" + hex(reply.msrs[i].high) + hex(reply.msrs[i].low).substr(2);
        }
        out.push_back({"VM-K01", "KVM private MSRs (kernel)", matches.empty() ? CHECK_GOOD : CHECK_BAD,
            "CPL=0; invalid-register controls faulted; CPUID hypervisor bit=" +
            std::to_string((reply.cpuid_ecx >> 31) & 1) + (matches.empty() ? "; all six KVM reads faulted" : "; " + matches)});
    }
    const auto firmware_error = [&](const std::string& why) {
        out.push_back({"VM-K02", "KVM/OVMF firmware-directory identifiers (kernel)", CHECK_ERROR, why});
    };
    if (reply.firmware_status == VMD_NOT_SUPPORTED) {
        // No discovered interface provides no successful negative measurement.
        return out;
    }
    if (reply.firmware_status) { firmware_error("firmware query status=" + hex(reply.firmware_status)); return out; }
    if (!(reply.firmware_features & 1) || (reply.firmware_features & ~3u) || reply.firmware_count > VMD_FWCFG_FILES) {
        firmware_error("invalid firmware feature bitmap or directory count"); return out;
    }
    std::set<std::string> names;
    std::set<std::uint16_t> selectors;
    std::string matches;
    for (unsigned i = 0; i < reply.firmware_count; i++) {
        const auto* entry = reply.directory + i * 64;
        const auto* end = std::find(entry + 8, entry + 64, 0);
        const auto selector = std::uint16_t(std::uint16_t(entry[4]) << 8 | entry[5]);
        if (end == entry + 64 || end == entry + 8 || entry[6] || entry[7] ||
            selector < 0x20 || selector >= 0x4000 || !selectors.insert(selector).second ||
            !std::all_of(entry + 8, end, [](std::uint8_t c) { return c >= 32 && c <= 126; })) {
            firmware_error("malformed firmware directory entry"); return out;
        }
        const std::string name(entry + 8, end);
        if (!names.insert(name).second) { firmware_error("duplicate firmware filename"); return out; }
        if (identifier(name)) { if (!matches.empty()) matches += "; "; matches += name; }
    }
    out.push_back({"VM-K02", "KVM/OVMF firmware-directory identifiers (kernel)", matches.empty() ? CHECK_GOOD : CHECK_BAD,
        "CPL=0; complete directory, entries=" + std::to_string(reply.firmware_count) +
        (matches.empty() ? "; no KVM/OVMF names" : "; " + matches)});
    if ((reply.firmware_features & 2) && !std::memcmp(reply.signature, "AMIF", 4) && !std::memcmp(reply.dma_signature, "AMIF CFG", 8))
        out.push_back({"VM-C01", "Customized firmware-configuration signatures (kernel)", CHECK_OBSERVATION,
            "AMIF / AMIF CFG with a validated compatible firmware directory; clue only"});
    return out;
}
}

namespace adversary {
std::vector<Result> evaluate_network(const Sample<Bytes>& response)
{
    static_assert(sizeof(VmdNetworkReply) == VMD_NETWORK_REPLY_SIZE, "network protocol layout");
    if (response.state == ReadState::NotApplicable) return {};
    const auto errors = [](const std::string& why) {
        return std::vector<Result>{{"NET-VM-01", "82574L hardwired PCIe capabilities (kernel)", CHECK_ERROR, why},
            {"NET-VM-02", "82574L NVM address-size legality (kernel)", CHECK_ERROR, why}};
    };
    if (response.state == ReadState::Error) return errors(response.reason);
    if (response.value.size() != sizeof(VmdNetworkReply)) return errors("network response has the wrong size");
    VmdNetworkReply r;
    std::memcpy(&r, response.value.data(), sizeof(r));
    if (r.version != VMD_NETWORK_VERSION || r.size != sizeof(r) || !r.cs || (r.cs & 3) || r.irql > 1)
        return errors("invalid network response version, size or execution context");
    if (r.status == VMD_NOT_SUPPORTED) return {};
    if (r.status) return errors("network query status=" + hex(r.status));
    if (r.bus > 255 || r.slot > 255 || std::memcmp(r.pci[0], r.pci[1], 256) ||
        r.eecd[0] != r.eecd[1] || std::memcmp(r.eeprom[0], r.eeprom[1], 128))
        return errors("invalid PCI location or unstable repeated network measurements");
    const auto* pci = r.pci[0];
    const auto u16 = [&](unsigned i) { return unsigned(pci[i]) | unsigned(pci[i + 1]) << 8; };
    const auto u32 = [&](unsigned i) { return u16(i) | u16(i + 2) << 16; };
    if (u16(0) != 0x8086 || u16(2) != 0x10d3 || (pci[14] & 0x7f) || !(u16(6) & 0x10))
        return errors("wrong PCI identity/header or missing capability list");
    std::set<unsigned> visited;
    unsigned cap = pci[0x34], express = 0;
    while (cap) {
        if (cap < 0x40 || cap > 0xfc || (cap & 3) || !visited.insert(cap).second)
            return errors("malformed or cyclic PCI capability list");
        if (pci[cap] == 0x10) {
            if (express || cap > 0xe8) return errors("duplicate or truncated PCIe capability");
            express = cap;
        }
        cap = pci[cap + 1];
    }
    if (!express) return errors("82574L PCIe capability was not read");
    const auto* words = r.eeprom[0];
    unsigned sum = 0;
    for (unsigned i = 0; i < 64; i++) sum += words[i];
    if ((sum & 0xffff) != 0xbaba || (words[0x12] & 0xc000) != 0x4000 ||
        (r.eecd[0] & 0x300) != 0x300)
        return errors("invalid/incomplete NVM image, signature or autoload state");
    const unsigned flags = u16(express + 2), devcap = u32(express + 4);
    if ((flags & 15) != 1 || (devcap & 7) > 5)
        return errors("unsupported PCIe version or reserved maximum payload encoding");
    std::vector<Result> out;
    const bool impossible = ((flags >> 4) & 15) != 0 || (devcap & 0x20);
    out.push_back({"NET-VM-01", "82574L hardwired PCIe capabilities (kernel)", impossible ? CHECK_BAD : CHECK_GOOD,
        "Intel 317694-016 sections 9.1.6.1.3/4 require type=0 and extended tags=0; type=" +
        std::to_string((flags >> 4) & 15) + "; extended tags=" + std::to_string(bool(devcap & 0x20))});
    const unsigned address_size = (r.eecd[0] >> 15) & 3;
    out.push_back({"NET-VM-02", "82574L NVM address-size legality (kernel)", address_size == 0 ? CHECK_BAD : CHECK_GOOD,
        "Intel section 10.2.2.3 reserves NVADDS=0; valid NVM signature/presence/autoload verified; NVADDS=" +
        std::to_string(address_size)});
    std::string mismatch;
    if ((words[10] & 2) && (words[11] != u16(0x2e) || words[12] != u16(0x2c)))
        mismatch = "subsystem NVM=" + hex(words[11]) + "/" + hex(words[12]) +
            " live=" + hex(u16(0x2e)) + "/" + hex(u16(0x2c));
    if (((words[0x1a] >> 8) & 1) != (devcap & 7)) {
        if (!mismatch.empty()) mismatch += "; ";
        mismatch += "supported payload NVM=" + std::to_string(128u << ((words[0x1a] >> 8) & 1)) +
            " live=" + std::to_string(128u << (devcap & 7));
    }
    if (!mismatch.empty()) out.push_back({"NET-C02", "82574L NVM/live autoload mismatch (kernel)", CHECK_OBSERVATION,
        mismatch + "; post-autoload EEPROM edits are not excluded by a read-only snapshot"});
    static const std::uint16_t templ[64] = {
        0,0,0,0x0420,0xf746,0x2010,0xffff,0xffff,0,0,0x026b,0,0x8086,0,0,0x8058,
        0,0x2001,0x7e7c,0xffff,0x1000,0x00c8,0,0x2704,0x6cc9,0x3150,0x070e,0x460b,0x2d84,0x0100,0xf000,0x0706,
        0x6000,0x0080,0x0f04,0x7fff,0x4f01,0xc600,0,0x20ff,0x0028,3,0,0,0,3,0,0xffff,
        0x0100,0xc000,0x121c,0xc007,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0,0x0120,0xffff,0
    };
    bool match = true;
    // MAC words and checksum are variable; checksum validity was checked above.
    for (unsigned i = 3; i < 63; i++) {
        const auto expected = (i == 11 || i == 13) ? 0x10d3 : templ[i];
        if (words[i] != expected) match = false;
    }
    if (match) out.push_back({"NET-CLUE-01", "QEMU 82574L EEPROM template (kernel)", CHECK_OBSERVATION,
        "all 64 words match after MAC/device-ID/checksum substitutions; programmable physical NVM can match"});
    return out;
}
}
