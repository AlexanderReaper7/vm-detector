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
