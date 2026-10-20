#include "../vm-detector/AntiVM/KernelProbe.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
using namespace adversary;
static unsigned assertions;
static void require(bool b, const char* why) { ++assertions; if (!b) { std::cerr << why << '\n'; std::exit(1); } }
static Bytes wire(const VmdNetworkReply& r) { const auto* p = reinterpret_cast<const std::uint8_t*>(&r); return Bytes(p, p + sizeof(r)); }
static auto rows(const VmdNetworkReply& r) { return evaluate_network(Sample<Bytes>::ok(wire(r))); }
static CheckOutcome outcome(const std::vector<Result>& v, const char* id) {
    const auto it = std::find_if(v.begin(), v.end(), [&](const Result& r) { return r.id == id; });
    require(it != v.end(), "missing expected row"); return it->outcome;
}
static void errors(const std::vector<Result>& v) {
    require(v.size() == 2 && outcome(v,"NET-VM-01") == CHECK_ERROR && outcome(v,"NET-VM-02") == CHECK_ERROR,
        "failed/malformed query must produce exactly two ERROR rows");
}
static VmdNetworkReply load(const char* name) {
    std::ifstream f(std::string("tests/fixtures/network-2026-10-19/") + name, std::ios::binary);
    require(bool(f),"missing fixture"); Bytes b(std::istreambuf_iterator<char>(f), {});
    require(b.size() == sizeof(VmdNetworkReply),"fixture size"); VmdNetworkReply r; std::memcpy(&r,b.data(),b.size()); return r;
}
static void checksum(VmdNetworkReply& r) {
    unsigned sum = 0; for (unsigned i=0;i<63;i++) sum+=r.eeprom[0][i];
    r.eeprom[0][63] = std::uint16_t(0xbaba-sum); std::memcpy(r.eeprom[1],r.eeprom[0],128);
}
static void mirror(VmdNetworkReply& r) { std::memcpy(r.pci[1],r.pci[0],256); }
int main() {
    const auto before=load("before.bin"), fixed=load("fixed-0000.bin");
    auto v=rows(before);
    require(outcome(v,"NET-VM-01")==CHECK_BAD && outcome(v,"NET-VM-02")==CHECK_BAD,"original kernel measurements detected");
    require(outcome(v,"NET-CLUE-01")==CHECK_OBSERVATION && outcome(v,"NET-C02")==CHECK_OBSERVATION,"template and autoload mismatch are observations");
    for (const char* name : {"fixed-0000.bin","fixed-1234.bin","live-20261020.bin"}) {
        const auto r=load(name); v=rows(r);
        require(v.size()==2 && outcome(v,"NET-VM-01")==CHECK_GOOD && outcome(v,"NET-VM-02")==CHECK_GOOD,"fixed device measurements pass without clues");
    }
    // Each immutable contradiction must be sufficient independently.
    auto r=fixed; r.pci[0][0xe2]|=0x90; mirror(r);
    require(outcome(rows(r),"NET-VM-01")==CHECK_BAD,"wrong endpoint type independently detected");
    r=fixed; r.pci[0][0xe4]|=0x20; mirror(r);
    require(outcome(rows(r),"NET-VM-01")==CHECK_BAD,"unsupported extended tags independently detected");
    r=fixed; r.eecd[0]=r.eecd[1]=0x300;
    require(outcome(rows(r),"NET-VM-02")==CHECK_BAD,"reserved address mode independently detected");
    r=fixed; r.eeprom[0][11]^=1; checksum(r); v=rows(r);
    require(outcome(v,"NET-VM-01")==CHECK_GOOD && outcome(v,"NET-VM-02")==CHECK_GOOD && outcome(v,"NET-C02")==CHECK_OBSERVATION,"post-autoload edit cannot create BAD");
    r=fixed; r.eeprom[0][26]^=0x100; checksum(r);
    require(outcome(rows(r),"NET-C02")==CHECK_OBSERVATION,"payload comparison uses NVM-selected capability");
    r=before; r.eeprom[0][42]^=1; checksum(r); v=rows(r);
    require(std::none_of(v.begin(),v.end(),[](const Result& x){return x.id=="NET-CLUE-01";}),"template clue requires full exact match");
    require(evaluate_network({}).empty(),"unrequested checks omitted");
    errors(evaluate_network(Sample<Bytes>::error("driver unavailable")));
    r=fixed; r.status=VMD_NOT_SUPPORTED; require(rows(r).empty(),"absent target omitted");
    const auto b=wire(fixed);
    for (std::size_t n=0;n<b.size();n++) errors(evaluate_network(Sample<Bytes>::ok(Bytes(b.begin(),b.begin()+n))));
    auto extra=b; extra.push_back(0); errors(evaluate_network(Sample<Bytes>::ok(extra)));
    for (unsigned k=0;k<23;k++) {
        r=fixed;
        switch(k) {
        case 0:r.version++;break; case 1:r.size--;break; case 2:r.cs=0x33;break;
        case 3:r.irql=2;break; case 4:r.status=0xc00000b5;break; case 5:r.bus=256;break;
        case 6:r.slot=256;break; case 7:r.pci[1][4]^=1;break; case 8:r.eecd[1]^=1;break;
        case 9:r.eeprom[1][0]^=1;break; case 10:r.pci[0][0]^=1;mirror(r);break;
        case 11:r.pci[0][14]=1;mirror(r);break; case 12:r.pci[0][6]&=~0x10;mirror(r);break;
        case 13:r.pci[0][0x34]=0x41;mirror(r);break; case 14:r.pci[0][0xe1]=0xe0;mirror(r);break;
        case 15:r.pci[0][0x34]=0xfc;r.pci[0][0xfc]=0x10;r.pci[0][0xfd]=0;mirror(r);break;
        case 16:r.pci[0][0xe0]=0x11;mirror(r);break; case 17:r.eeprom[0][0]^=1;std::memcpy(r.eeprom[1],r.eeprom[0],128);break;
        case 18:r.eeprom[0][0x12]&=0x3fff;checksum(r);break; case 19:r.eecd[0]=r.eecd[1]=0;break;
        case 20:r.pci[0][0xe2]=2;mirror(r);break; case 21:r.pci[0][0xe4]|=7;mirror(r);break;
        case 22:r.status=0x80000005;break;
        }
        errors(rows(r));
    }
    std::cout << "Network assertions passed: " << assertions << '\n';
}
