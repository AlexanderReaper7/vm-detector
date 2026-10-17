#include "../vm-detector/AntiVM/Adversary.h"
#include <cpuid.h>
#include <cstring>
#include <iostream>

// Linux host control for the actual CPU. This is separate from the portable fixture suite.
int main()
{
	adversary::Cpu cpu;
	unsigned a,b,c,d;
	cpu.max_basic=__get_cpuid_max(0,nullptr);
	cpu.max_extended=__get_cpuid_max(0x80000000,nullptr);
	__cpuid_count(0,0,a,b,c,d);
	char vendor[13]{};
	std::memcpy(vendor,&b,4); std::memcpy(vendor+4,&d,4); std::memcpy(vendor+8,&c,4);
	cpu.vendor=vendor;
	if (cpu.max_extended>=0x80000004) {
		char brand[49]{};
		for (unsigned i=0;i<3;++i) {
			__cpuid_count(0x80000002+i,0,a,b,c,d);
			const unsigned regs[4]={a,b,c,d}; std::memcpy(brand+i*16,regs,16);
		}
		cpu.brand=brand;
	}
	for (unsigned id:{1u,6u,7u,0x80000001u,0x80000005u,0x80000006u,0x80000007u,0x80000008u,0x8000000au,0x8000001fu}) {
		if (id<0x80000000u ? id>cpu.max_basic : id>cpu.max_extended) continue;
		__cpuid_count(id,0,a,b,c,d); cpu.leaves[id]={a,b,c,d};
	}
	adversary::Snapshot snapshot; snapshot.cpu=adversary::Sample<adversary::Cpu>::ok(cpu);
	bool failed=false;
	for (const auto& result:adversary::evaluate(snapshot)) {
		std::cout << result.id << " outcome=" << result.outcome << ' ' << result.evidence << '\n';
		if (result.outcome==CHECK_BAD || result.outcome==CHECK_ERROR) failed=true;
	}
	std::cout << "CPUID.80000008 EBX=0x" << std::hex << cpu.leaves[0x80000008][1] << '\n';
	return failed?1:0;
}
