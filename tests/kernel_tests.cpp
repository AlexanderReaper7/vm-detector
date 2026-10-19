#include "../vm-detector/AntiVM/KernelProbe.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>

using namespace adversary;
static unsigned assertions;
static void require(bool ok, const char* message)
{
    ++assertions;
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
static Bytes wire(const VmdKernelReply& reply)
{
    const auto* begin = reinterpret_cast<const std::uint8_t*>(&reply);
    return Bytes(begin, begin + sizeof(reply));
}
static std::vector<Result> rows(const VmdKernelReply& reply)
{
    return evaluate_kernel(Sample<Bytes>::ok(wire(reply)));
}
static CheckOutcome outcome(const std::vector<Result>& results, const char* id)
{
    const auto it = std::find_if(results.begin(), results.end(), [&](const Result& r) { return r.id == id; });
    require(it != results.end(), "expected check exists");
    return it->outcome;
}
static VmdKernelReply capture(const char* name)
{
    std::ifstream file(std::string("tests/fixtures/kernel-2026-10-19/") + name);
    require(bool(file), "open original kernel output");
    VmdKernelReply r{};
    r.version = VMD_KERNEL_VERSION;
    r.size = sizeof(r);
    const std::uint32_t ids[] = {0x4b564d00, 0x4b564d01, 0x4b564d02, 0x4b564d03,
        0x4b564d04, 0x4b564d05, 0xdeadbeef, 0xffffffff};
    unsigned observed = 0, count = 0;
    // Translate recorded text into the protocol for replay. These are not
    // claimed binary captures from the new companion driver.
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("KPROBE version=", 0) == 0) {
            auto cs = line.find("CS="), irql = line.find("IRQL=");
            require(cs != std::string::npos && irql != std::string::npos, "execution context recorded");
            r.cs = std::stoul(line.substr(cs + 3), nullptr, 16);
            r.irql = std::stoul(line.substr(irql + 5));
        }
        if (line.rfind("CPUID 00000001:", 0) == 0)
            r.cpuid_ecx = std::stoul(line.substr(line.find("ECX=") + 4), nullptr, 16);
        unsigned index, status;
        unsigned long long value;
        if (line.rfind("RDMSR ", 0) == 0) {
            require(std::sscanf(line.c_str(), "RDMSR %x", &index) == 1, "MSR index parsed");
            const auto it = std::find(std::begin(ids), std::end(ids), index);
            if (it == std::end(ids)) continue;
            auto& m = r.msrs[it - ids];
            m.index = index;
            if (std::sscanf(line.c_str(), "RDMSR %x EXCEPTION %x", &index, &status) == 2) m.status = status;
            else {
                require(std::sscanf(line.c_str(), "RDMSR %x OK %llx", &index, &value) == 2, "successful MSR parsed");
                m.low = std::uint32_t(value); m.high = std::uint32_t(value >> 32);
            }
            ++observed;
        }
        if (line.rfind("FWCFG selector=0000 signature=", 0) == 0) {
            std::istringstream bytes(line.substr(line.find("signature=") + 10));
            for (auto& byte : r.signature) { bytes >> std::hex >> index; byte = std::uint8_t(index); }
        }
        if (line.rfind("FWCFG DMA signature=", 0) == 0) {
            std::istringstream bytes(line.substr(20));
            for (auto& byte : r.dma_signature) { bytes >> std::hex >> index; byte = std::uint8_t(index); }
        }
        if (line.rfind("FWCFG selector=0001 id=", 0) == 0) {
            std::istringstream bytes(line.substr(23));
            for (unsigned i = 0; i < 4; i++) { bytes >> std::hex >> index; r.firmware_features |= index << (i * 8); }
        }
        if (line.rfind("FWCFG directory count=", 0) == 0) r.firmware_count = std::stoul(line.substr(22));
        if (line.rfind("FWCFG file ", 0) == 0) {
            unsigned size, selector; char name[56]{};
            require(std::sscanf(line.c_str(), "FWCFG file size=%u select=%x name=%55s", &size, &selector, name) == 3,
                "firmware record parsed");
            require(count < VMD_FWCFG_FILES, "captured directory bounded");
            auto* entry = r.directory + count++ * 64;
            for (unsigned j = 0; j < 4; j++) entry[j] = std::uint8_t(size >> (24 - j * 8));
            entry[4] = std::uint8_t(selector >> 8); entry[5] = std::uint8_t(selector);
            std::memcpy(entry + 8, name, std::strlen(name));
        }
    }
    require(observed == VMD_MSR_COUNT && count == r.firmware_count, "all required captured data present");
    require(r.cs == 0x10 && r.firmware_features == 3, "actual context and feature bitmap");
    return r;
}

int main()
{
    std::ifstream live_file("tests/fixtures/kernel-2026-10-19/live-response.bin", std::ios::binary);
    require(bool(live_file), "open actual companion-driver response");
    Bytes live(std::istreambuf_iterator<char>(live_file), {});
    const auto live_rows = evaluate_kernel(Sample<Bytes>::ok(live));
    require(outcome(live_rows, "VM-K01") == CHECK_GOOD && outcome(live_rows, "VM-K02") == CHECK_GOOD &&
        outcome(live_rows, "VM-C01") == CHECK_OBSERVATION, "actual live wire response matches detector output");
    const auto before = capture("before.txt"), fixed = capture("fixed.txt");
    require(outcome(rows(before), "VM-K01") == CHECK_BAD, "captured pre-fix KVM MSRs detected");
    require(outcome(rows(before), "VM-K02") == CHECK_BAD, "captured pre-fix firmware names detected");
    require(outcome(rows(fixed), "VM-K01") == CHECK_GOOD, "captured Windows exceptions clear MSR result");
    require(outcome(rows(fixed), "VM-K02") == CHECK_GOOD, "captured deployed directory clears names result");
    require(outcome(rows(fixed), "VM-C01") == CHECK_OBSERVATION, "AMIF remains only a clue");
    require(rows(fixed).size() == 3, "no duplicate VGA scoring");
    for (unsigned i = 0; i < 6; i++) {
        auto r = fixed; r.msrs[i].status = 0;
        require(outcome(rows(r), "VM-K01") == CHECK_BAD, "each private MSR can identify the ABI");
    }
    for (unsigned i = 6; i < 8; i++) {
        auto r = before; r.msrs[i].status = 0;
        require(outcome(rows(r), "VM-K01") == CHECK_ERROR, "blanket successful reads are inconclusive");
    }
    auto r = fixed; r.msrs[0].status = 0xc0000005;
    require(outcome(rows(r), "VM-K01") == CHECK_ERROR, "unexpected exception is not absence");
    r = fixed; r.msrs[0].index = r.msrs[1].index;
    require(outcome(rows(r), "VM-K01") == CHECK_ERROR, "duplicated MSR cannot substitute for a required read");
    r = fixed; r.firmware_status = VMD_NOT_SUPPORTED;
    require(rows(r).size() == 1, "undiscovered interface produces no firmware or clue row");
    r = fixed; r.firmware_status = 0x80000005;
    require(rows(r).size() == 2 && outcome(rows(r), "VM-K02") == CHECK_ERROR, "incomplete scan is ERROR, clue omitted");
    for (unsigned field = 0; field < 5; field++) {
        r = fixed;
        if (field == 0) r.version++;
        if (field == 1) r.size--;
        if (field == 2) r.cs = 0;
        if (field == 3) r.cs = 0x33;
        if (field == 4) r.irql = 2;
        require(outcome(rows(r), "VM-K01") == CHECK_ERROR && outcome(rows(r), "VM-K02") == CHECK_ERROR,
            "invalid driver header cannot establish kernel execution");
    }
    const auto bytes = wire(fixed);
    for (std::size_t n = 0; n < bytes.size(); n++) {
        const auto result = evaluate_kernel(Sample<Bytes>::ok(Bytes(bytes.begin(), bytes.begin() + n)));
        require(result.size() == 2 && outcome(result, "VM-K01") == CHECK_ERROR && outcome(result, "VM-K02") == CHECK_ERROR,
            "every truncated kernel response is an error");
    }
    auto extra = bytes; extra.push_back(0);
    require(outcome(evaluate_kernel(Sample<Bytes>::ok(extra)), "VM-K01") == CHECK_ERROR, "oversized response rejected");
    for (unsigned kind = 0; kind < 7; kind++) {
        r = fixed;
        if (kind == 0) r.firmware_count = VMD_FWCFG_FILES + 1;
        if (kind == 1) std::memset(r.directory + 8, 'x', 56);
        if (kind == 2) r.directory[6] = 1;
        if (kind == 3) r.directory[4] = 0x40;
        if (kind == 4) std::memcpy(r.directory + 64, r.directory, 64);
        if (kind == 5) r.directory[8] = 1;
        if (kind == 6) r.firmware_features = 0;
        require(outcome(rows(r), "VM-K02") == CHECK_ERROR && rows(r).size() == 2,
            "malformed directory never produces a negative or clue result");
    }
    r = fixed; r.firmware_count = 1;
    for (const char* name : {"genroms/kvmvapic.bin", "opt/ovmf/X-PciMmio64Mb", "opt/ovmf/another-setting"}) {
        std::memset(r.directory + 8, 0, 56); std::memcpy(r.directory + 8, name, std::strlen(name));
        require(outcome(rows(r), "VM-K02") == CHECK_BAD, "explicit ROM and OVMF namespace detected");
    }
    for (const char* name : {"genroms/kvmvapic.bin.old", "opt/ovmfoo/setting", "etc/notes-about-qemu"}) {
        std::memset(r.directory + 8, 0, 56); std::memcpy(r.directory + 8, name, std::strlen(name));
        require(outcome(rows(r), "VM-K02") == CHECK_GOOD, "close or incidental strings do not become identifiers");
    }
    r = fixed; std::memcpy(r.signature, "QEMU", 4); std::memcpy(r.dma_signature, "QEMU CFG", 8);
    require(rows(r).size() == 2, "AMIF-specific observation does not fire on another signature");
    require(evaluate_kernel({}).empty(), "unrequested kernel checks are skipped entirely");
    const auto unavailable = evaluate_kernel(Sample<Bytes>::error("driver unavailable"));
    require(unavailable.size() == 2 && outcome(unavailable, "VM-K01") == CHECK_ERROR &&
        outcome(unavailable, "VM-K02") == CHECK_ERROR, "requested but unavailable driver is ERROR");
    std::cout << "Kernel assertions passed: " << assertions << '\n';
}
