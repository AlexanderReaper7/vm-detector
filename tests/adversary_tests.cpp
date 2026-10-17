#include "../vm-detector/AntiVM/Adversary.h"
#include "../vm-detector/Shared/stats.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <sstream>

using namespace adversary;
static unsigned assertions=0;
void require(bool ok,const std::string& message)
{
	++assertions;
	if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
Bytes load(const std::string& name)
{
	std::ifstream f("tests/fixtures/adversary-2026-10-16/"+name,std::ios::binary);
	require(bool(f),"open fixture "+name);
	return Bytes(std::istreambuf_iterator<char>(f),{});
}
const Result& result(const std::vector<Result>& rows,const std::string& id)
{
	auto it=std::find_if(rows.begin(),rows.end(),[&](const Result& r){return r.id==id;});
	require(it!=rows.end(),"result exists: "+id);
	return *it;
}
bool any(const std::vector<Result>& rows,CheckOutcome outcome)
{
	return std::any_of(rows.begin(),rows.end(),[&](const Result& r){return r.outcome==outcome;});
}
void put32(Bytes& b,std::size_t p,std::uint32_t v)
{
	for(unsigned i=0;i<4;++i) b[p+i]=std::uint8_t(v>>(8*i));
}
void checksum(Bytes& b)
{
	b[9]=0; unsigned sum=0; for(auto x:b) sum+=x; b[9]=std::uint8_t(0-sum);
}
void replace(Bytes& b,const std::string& before,const std::string& after)
{
	require(after.size()<=before.size(),"replacement fits");
	auto it=std::search(b.begin(),b.end(),before.begin(),before.end());
	require(it!=b.end(),"replacement target exists: "+before);
	std::fill(it,it+before.size(),' '); std::copy(after.begin(),after.end(),it);
}

Bytes latest(const std::string& file)
{
	std::ifstream f("tests/fixtures/adversary-2026-10-17/"+file,std::ios::binary);
	require(bool(f),"open latest fixture "+file);
	return Bytes(std::istreambuf_iterator<char>(f),{});
}
Bytes nvme_qtest_fixture(const std::string& file)
{
	std::ifstream f("tests/fixtures/nvme-oui-2026-10-18/"+file,std::ios::binary);
	require(bool(f),"open NVMe qtest fixture "+file);
	return Bytes(std::istreambuf_iterator<char>(f),{});
}
bool has_id(const std::vector<Result>& rows,const std::string& id)
{
	return std::any_of(rows.begin(),rows.end(),[&](const Result& r){return r.id==id;});
}
void latest_tests()
{
	for (const auto& file:{"hid-read-v2.txt","hid-read-repeat.txt","hid-fixed.txt"}) {
		const auto b=latest(file);
		std::string log;
		if (b.size()>=2 && b[0]==0xff && b[1]==0xfe) {
			require(b.size()%2==0,"UTF16LE fixture has complete code units");
			for (std::size_t i=2;i<b.size();i+=2) { require(!b[i+1],"HID fixture contains ASCII text"); log+=char(b[i]); }
		} else {
			require(b.size()>=3 && b[0]==0xef && b[1]==0xbb && b[2]==0xbf,"repeated fixture is UTF8 with BOM");
			log.assign(b.begin()+3,b.end());
		}
		Snapshot s; std::vector<Hid> devices;
		std::istringstream stream(log); std::string line;
		while (std::getline(stream,line)) {
			if (line.rfind("HID path=",0)==0) devices.push_back({line,{}});
			if (line.rfind("HID indexed=",0)!=0 || line.find("ok=True")==std::string::npos) continue;
			const auto index=std::stoul(line.substr(12));
			const auto begin=line.find("text='")+6, end=line.rfind('\'');
			require(!devices.empty() && end>=begin,"indexed response follows a device path");
			devices.back().indexed_strings[unsigned(index)]=Sample<std::string>::ok(line.substr(begin,end-begin));
		}
		require(devices.size()==2,"two recorded HID interfaces");
		s.hid=decltype(s.hid)::ok(devices); auto rows=evaluate(s);
		if (std::string(file)=="hid-fixed.txt") {
			require(rows.size()==1 && result(rows,"CODEX-004").outcome==CHECK_GOOD,"actual fixed-QEMU capture clears HID identifier");
			for (const auto& device:devices)
				require(device.indexed_strings.at(3).value.empty(),"fixed device successfully returns empty index 3");
		} else require(std::count_if(rows.begin(),rows.end(),[](const Result& r){return r.id=="CODEX-004" && r.outcome==CHECK_BAD;})==1,
			"both captured devices produce one shared HID-identifier result");
		for (auto& device:s.hid.value) device.indexed_strings[3]=Sample<std::string>::ok("Physical tablet");
		require(!any(evaluate(s),CHECK_BAD),"one-field replacement on both devices removes only the identifier");
	}
	Snapshot s; Hid h{"physical USB",{{1,Sample<std::string>::ok("Logitech")},{3,{}}}};
	s.hid=decltype(s.hid)::ok({h});
	require(result(evaluate(s),"CODEX-004").outcome==CHECK_GOOD,"missing optional index is not QEMU or query failure");
	s.hid.value[0].indexed_strings.clear();
	require(evaluate(s).empty(),"no readable optional strings produces no row");
	s.hid.value[0].indexed_strings[3]=Sample<std::string>::error("access denied");
	require(evaluate(s).size()==1 && result(evaluate(s),"CODEX-004").outcome==CHECK_ERROR,"real HID query error is visible without GOOD");
	s.hid.value[0].indexed_strings[1]=Sample<std::string>::ok("Logitech");
	require(!any(evaluate(s),CHECK_GOOD) && any(evaluate(s),CHECK_ERROR),"partial negative HID scan cannot become GOOD after required query failure");
	s.hid.value[0].indexed_strings[1]=Sample<std::string>::ok("QEMU USB Tablet");
	require(any(evaluate(s),CHECK_BAD) && any(evaluate(s),CHECK_ERROR),"explicit positive HID evidence survives a separate query error");
	s.hid=decltype(s.hid)::error("enumeration failure");
	require(result(evaluate(s),"CODEX-004").outcome==CHECK_ERROR,"HID enumeration failure is ERROR");
	s={}; Disk disk; disk.path="captured namespace 1";
	disk.identify=Sample<Bytes>::ok(latest("nvme-controller.bin"));
	disk.namespace_identify=Sample<Bytes>::ok(latest("nvme-namespace.bin"));
	s.disks=decltype(s.disks)::ok({disk});
	require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_BAD,"captured NVMe zero-total/usable namespace contradiction");
	require(result(evaluate(s),"CODEX-002-OUI").outcome==CHECK_OBSERVATION,"captured QEMU OUI is only an observation");
	for (const auto& profile:{"samsung","intel"}) {
		Snapshot fixed; Disk captured; captured.path=profile;
		captured.identify=Sample<Bytes>::ok(nvme_qtest_fixture(std::string(profile)+"-controller.bin"));
		captured.namespace_identify=Sample<Bytes>::ok(nvme_qtest_fixture(std::string(profile)+"-namespace.bin"));
		fixed.disks=decltype(fixed.disks)::ok({captured});
		const auto rows=evaluate(fixed);
		require(result(rows,"CODEX-002-OUI").outcome==CHECK_GOOD,"actual fixed-QEMU IEEE response clears the OUI clue");
		require(result(rows,"CODEX-002-CAP").outcome==CHECK_BAD,"OUI-only fix preserves the independent capacity contradiction");
		require(!any(rows,CHECK_ERROR),"both captured NVMe Identify payloads pass validation");
	}
	for (unsigned byte=280;byte<296;++byte) {
		s.disks.value[0]=disk; s.disks.value[0].identify.value[byte]=1;
		require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_GOOD,"each byte of 128-bit TNVMCAP can establish nonzero total");
	}
	s.disks.value[0]=disk; s.disks.value[0].identify.value[256]&=~8;
	require(!has_id(evaluate(s),"CODEX-002-CAP"),"field is not required when NS management absent");
	s.disks.value[0]=disk; put32(s.disks.value[0].identify.value,80,0x00020000);
	require(!has_id(evaluate(s),"CODEX-002-CAP"),"unknown spec version is not inferred from NVMe 1.4 rule");
	s.disks.value[0]=disk; s.disks.value[0].namespace_identify.value[24]|=1;
	require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_GOOD,"thin provisioning alone cannot satisfy strict predicate");
	s.disks.value[0]=disk; s.disks.value[0].namespace_identify=Sample<Bytes>::error("query failed");
	require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_ERROR,"namespace query failure is ERROR");
	for (std::size_t n=0;n<4096;++n) {
		s.disks.value[0]=disk; s.disks.value[0].namespace_identify.value.resize(n);
		require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_ERROR,"every truncated namespace payload is ERROR");
	}
	s.disks.value[0]=disk; s.disks.value[0].namespace_identify.value[26]=15;
	require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_ERROR,"unsupported LBA format index rejected");
	s.disks.value[0]=disk; s.disks.value[0].namespace_identify.value[130]=64;
	require(result(evaluate(s),"CODEX-002-CAP").outcome==CHECK_ERROR,"invalid LBA shift rejected");
	s={}; s.acpi=decltype(s.acpi)::ok({latest("DSDT.bin")});
	require(result(evaluate(s),"CODEX-003").outcome==CHECK_OBSERVATION,"saved DSDT contains both port declaration templates");
	Bytes ports{0x47,1,0x10,5,0x10,5,1,12};
	auto pos=std::search(s.acpi.value[0].begin(),s.acpi.value[0].end(),ports.begin(),ports.end());
	require(pos!=s.acpi.value[0].end(),"port template located in captured table");
	*pos=0x46; checksum(s.acpi.value[0]);
	require(result(evaluate(s),"CODEX-003").outcome==CHECK_GOOD,"changing one port template clears the profile clue");
	s.acpi.value[0][9]^=1;
	require(any(evaluate(s),CHECK_ERROR) && !has_id(evaluate(s),"CODEX-003"),"invalid ACPI cannot establish the declaration clue");
	s={}; s.smbios=Sample<Bytes>::ok(load("smbios.bin"));
	require(result(evaluate(s),"OPUS-010").outcome==CHECK_OBSERVATION,"captured single-slot array equals installed memory");
	require(result(evaluate(s),"OPUS-016").outcome==CHECK_OBSERVATION,"captured legacy SMBIOS and small inventory");
	const Bytes array_header{16,23,0,16};
	auto array=std::search(s.smbios.value.begin(),s.smbios.value.end(),array_header.begin(),array_header.end());
	require(array!=s.smbios.value.end(),"captured memory array located");
	const auto array_offset=std::size_t(array-s.smbios.value.begin());
	put32(s.smbios.value,array_offset+7,33554432);
	require(result(evaluate(s),"OPUS-010").outcome==CHECK_GOOD,"larger maximum clears array clue");
	s.smbios.value[1]=3; s.smbios.value[2]=6;
	require(result(evaluate(s),"OPUS-016").outcome==CHECK_GOOD,"modern entry point clears legacy-version clue");
	s={}; Cpu inventory_cpu; inventory_cpu.vendor="AuthenticAMD"; inventory_cpu.brand="Ryzen";
	s.cpu=Sample<Cpu>::ok(inventory_cpu); s.acpi=decltype(s.acpi)::ok({latest("DSDT.bin")});
	require(result(evaluate(s),"OPUS-009").outcome==CHECK_OBSERVATION,"AMD platform table absence is observational");
	Bytes ivrs(48); std::copy_n("IVRS",4,ivrs.begin()); put32(ivrs,4,48); checksum(ivrs);
	s.acpi.value.push_back(ivrs);
	require(result(evaluate(s),"OPUS-009").outcome==CHECK_GOOD,"an IVRS table removes the all-three-absent clue");
	require(result(evaluate(s),"OPUS-008").outcome==CHECK_GOOD,"captured patched OEM identity is not EDK2");
	std::copy_n("INTEL ",6,s.acpi.value[0].begin()+10); std::copy_n("EDK2    ",8,s.acpi.value[0].begin()+16); checksum(s.acpi.value[0]);
	require(result(evaluate(s),"OPUS-008").outcome==CHECK_OBSERVATION,"changing only header OEM identity triggers EDK2 clue");
	s={}; Cpu cpu; cpu.vendor="AuthenticAMD"; cpu.brand="AMD Ryzen 5 9600X";
	cpu.max_extended=0x80000022; cpu.leaves[1]={0x00b40f40,0,0,0};
	cpu.leaves[0x80000007]={0,0,0,0x100}; s.cpu=Sample<Cpu>::ok(cpu);
	require(result(evaluate(s),"OPUS-006").outcome==CHECK_OBSERVATION,"missing CPB is a clue");
	require(result(evaluate(s),"OPUS-015").outcome==CHECK_OBSERVATION,"zero SME leaf is a clue");
	s.cpu.value.leaves[0x80000007][3]|=1u<<9; s.cpu.value.leaves[0x8000001f]={1,0xb3,0,0};
	require(result(evaluate(s),"OPUS-006").outcome==CHECK_GOOD && result(evaluate(s),"OPUS-015").outcome==CHECK_GOOD,"deployed CPU fixes clear both clues");
	s.devices=decltype(s.devices)::ok({"ACPI\\PNP0303\\0","ACPI\\PNP0F13\\0","PCI\\VEN_8086&DEV_29C0&REV_00"});
	s.pci_buses=decltype(s.pci_buses)::ok({0,0,0});
	require(result(evaluate(s),"OPUS-013").outcome==CHECK_OBSERVATION && result(evaluate(s),"OPUS-017").outcome==CHECK_OBSERVATION,"legacy pair and flat PCI are clues");
	s.pci_buses.value.push_back(1);
	require(result(evaluate(s),"OPUS-017").outcome==CHECK_GOOD,"second bus removes flat PCI clue");
}

int main()
{
	latest_tests();
	require(evaluate({}).empty(),"inapplicable checks produce no rows");
	Snapshot s;
	s.devices=decltype(s.devices)::ok({"ACPI\\QEMU0002\\X","PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02\\X"});
	auto rows=evaluate(s);
	for(const auto& id:{"VM-001","VM-002","VM-003/011"})
		require(result(rows,id).outcome==CHECK_BAD,std::string("recorded identity detected: ")+id);
	s.devices=decltype(s.devices)::ok({"ACPI\\PNP0A08\\0","PCI\\VEN_1002&DEV_13C0&SUBSYS_7D751462&REV_C2\\X",
		"ROOT\\NOTE_ACPI\\QEMU0002\\X","PCI\\VEN_1234&DEV_1112&SUBSYS_11001AF4F&REV_00\\X"});
	require(!any(evaluate(s),CHECK_BAD),"physical IDs and near matches do not trigger strict identity checks");
	for (const auto& r:evaluate(s)) if (r.outcome==CHECK_GOOD)
		require(r.evidence.empty(),"unmatched rules do not print their positive evidence text");
	s.devices=decltype(s.devices)::error("access denied"); rows=evaluate(s);
	require(rows.size()==1 && rows[0].outcome==CHECK_ERROR,"query failure cannot become GOOD");

	s={}; s.smbios=Sample<Bytes>::ok(load("smbios.bin")); rows=evaluate(s);
	require(result(rows,"VM-014").outcome==CHECK_BAD,"raw SMBIOS processor record names QEMU");
	const auto original=s.smbios.value;
	replace(s.smbios.value,"pc-q35-11.1","AMD Ryzen");
	require(result(evaluate(s),"VM-014").outcome==CHECK_GOOD,"changing only processor string removes that detection");
	s.smbios.value=original;
	for(std::size_t n=0;n<original.size();++n) {
		s.smbios.value.assign(original.begin(),original.begin()+n);
		if (n>=8) put32(s.smbios.value,4,std::uint32_t(n-8));
		rows=evaluate(s);
		require(any(rows,CHECK_ERROR) && !any(rows,CHECK_BAD),"every truncated SMBIOS prefix is an error");
	}
	s.smbios.value=original;
	const Bytes processor_header{4,42,0,4};
	auto processor=std::search(s.smbios.value.begin(),s.smbios.value.end(),processor_header.begin(),processor_header.end());
	require(processor!=s.smbios.value.end(),"fixture processor structure located");
	*(processor+16)=255;
	require(any(evaluate(s),CHECK_ERROR) && !any(evaluate(s),CHECK_BAD),"invalid processor string index cannot become GOOD");
	s.smbios.value=original;
	// Corruption after the otherwise detectable processor record must invalidate the parse.
	s.smbios.value.back()=1;
	require(any(evaluate(s),CHECK_ERROR) && !any(evaluate(s),CHECK_BAD),"malformed tail is not accepted as valid firmware");

	s={}; const auto dsdt=load("DSDT.bin");
	s.acpi=decltype(s.acpi)::ok({dsdt}); rows=evaluate(s);
	require(result(rows,"VM-017").outcome==CHECK_BAD,"raw DSDT contains QEMU identity");
	auto changed=dsdt; replace(changed,"QEMU0002","PNP0C02"); checksum(changed);
	s.acpi.value={changed};
	require(result(evaluate(s),"VM-017").outcome==CHECK_GOOD,"removing ACPI identity clears only its strict check");
	s.acpi.value={load("SSDT_0.bin")};
	require(result(evaluate(s),"VM-045").outcome==CHECK_OBSERVATION,"literal thermal method is an observation");
	s.smbios=Sample<Bytes>::ok(original);
	require(result(evaluate(s),"VM-013").outcome==CHECK_OBSERVATION,"MSI is recognized by its actual Micro-Star manufacturer string");
	s.smbios={};
	s.acpi.value={load("APIC_0.bin")};
	require(result(evaluate(s),"VM-036").outcome==CHECK_OBSERVATION,"recorded MADT pattern recognized");
	s.acpi.value[0][45]=0; checksum(s.acpi.value[0]);
	require(any(evaluate(s),CHECK_ERROR),"zero-length MADT entry fails without looping");
	for(std::size_t n=0;n<dsdt.size();++n) {
		s.acpi.value={Bytes(dsdt.begin(),dsdt.begin()+n)};
		rows=evaluate(s);
		require(any(rows,CHECK_ERROR) && !any(rows,CHECK_BAD),"every truncated ACPI prefix is an error");
	}
	changed=dsdt; changed[100]^=1; s.acpi.value={changed};
	require(any(evaluate(s),CHECK_ERROR),"bad ACPI checksum is an error");

	s={}; Disk d; d.path="recorded NVMe"; d.identify=Sample<Bytes>::ok(load("nvme_identify_ctrl.bin"));
	s.disks=decltype(s.disks)::ok({d});
	require(result(evaluate(s),"VM-024").outcome==CHECK_BAD,"raw NVMe Identify names QEMU");
	replace(d.identify.value,"nqn.2019-08.org.qemu:","nqn.1994-11.samsung:");
	s.disks.value={d};
	require(result(evaluate(s),"VM-024").outcome==CHECK_GOOD,"realistic NVMe NQN is not a QEMU identity");
	d.smart=Sample<Bytes>::ok(Bytes(512)); d.smart.value[1]=0x43; d.smart.value[2]=1;
	d.smart.value[128]=3; // Power-on hours legitimately increase while the guest runs.
	s.disks.value={d};
	require(result(evaluate(s),"VM-025").outcome==CHECK_OBSERVATION,"SMART profile does not require counters to remain zero");
	d.smart.value[3]=100; d.smart.value[4]=10; s.disks.value={d};
	require(result(evaluate(s),"VM-025").outcome==CHECK_GOOD,"normal spare values remove the SMART observation");
	s={}; s.bios_versions=decltype(s.bios_versions)::ok({"ALASKA - 1","A.32","EDK II - 10000"});
	require(result(evaluate(s),"VM-005").outcome==CHECK_OBSERVATION,"BIOS version comes from Windows inventory rather than raw SMBIOS");

	// Transport validation uses returned bytes and reported offsets, not hardcoded byte 48.
	Bytes response(48+4096); put32(response,0,48); put32(response,4,48); put32(response,8,3);
	put32(response,12,1); put32(response,24,40); put32(response,28,4096);
	const auto identify=load("nvme_identify_ctrl.bin"); std::copy(identify.begin(),identify.end(),response.begin()+48);
	require(nvme_payload(response,4096,1).value==identify,"valid NVMe response yields exact bytes");
	for(std::size_t n=0;n<response.size();++n)
		require(nvme_payload(Bytes(response.begin(),response.begin()+n),4096,1).state==ReadState::Error,"truncated IOCTL never succeeds");
	auto moved=response; moved.insert(moved.begin()+48,16,0); put32(moved,24,56);
	require(nvme_payload(moved,4096,1).value==identify,"non-default payload offset is respected");
	for(auto offset:{0u,39u,0xfffffff0u,0xffffffffu}) {
		put32(response,24,offset);
		require(nvme_payload(response,4096,1).state==ReadState::Error,"invalid offset rejected without overflow");
	}

	s={}; s.tpm=Sample<Tpm>::ok({"IBM ","SW   TPM        "});
	require(result(evaluate(s),"VM-027").outcome==CHECK_BAD,"software TPM vendor identity detected");
	s.tpm=Sample<Tpm>::ok({"IBM ","physical vendor"});
	require(result(evaluate(s),"VM-027").outcome==CHECK_GOOD,"IBM manufacturer alone is not a VM assertion");
	s={}; s.certificates=decltype(s.certificates)::ok({{"swtpm-localca","adversary:UUID"}});
	require(result(evaluate(s),"VM-039").outcome==CHECK_BAD,"swtpm certificate issuer detected");
	s.certificates.value={{"AMD-fTPM-RSA-ICA","physical TPM"}};
	require(result(evaluate(s),"VM-039").outcome==CHECK_GOOD,"physical TPM certificate not detected");
	s={}; s.uefi.boot_order_marker=Sample<Bytes>::error("privilege not held");
	require(result(evaluate(s),"VM-031").outcome==CHECK_ERROR,"UEFI permission failure is ERROR");
	s.uefi.boot_order_marker=Sample<Bytes>::ok({});
	require(result(evaluate(s),"VM-031").outcome==CHECK_GOOD,"successful not-found UEFI result is GOOD");
	s.uefi.boot_order_marker=Sample<Bytes>::ok({1});
	require(result(evaluate(s),"VM-031").outcome==CHECK_BAD,"OVMF variable detected");
	s={}; Cpu c; c.vendor="AuthenticAMD"; c.max_extended=0x80000008; c.leaves[0x80000008]={0,1u<<25,0,0};
	s.cpu=Sample<Cpu>::ok(c);
	require(result(evaluate(s),"VM-043").outcome==CHECK_BAD,"virtual-only CPUID bit detected");
	s.cpu.value.leaves[0x80000008][1]=0;
	require(result(evaluate(s),"VM-043").outcome==CHECK_GOOD,"feature-absent control clears CPUID detection");
	s.cpu.value.max_basic=7;
	s.cpu.value.leaves[7]={0,0,0,0x10000110};
	require(result(evaluate(s),"VM-021").outcome==CHECK_GOOD,"physical strix CPUID bit 28 alone is not suspicious");
	s.cpu.value.leaves[7][3]=0x9c000110;
	require(result(evaluate(s),"VM-021").outcome==CHECK_OBSERVATION,"reported speculation combination remains an observation");
	s={}; s.gateways=decltype(s.gateways)::ok({"192.168.122.1 52:54:00:68:a5:d0"});
	s.storage_history=decltype(s.storage_history)::ok({"QEMU / QEMU DVD-ROM"});
	rows=evaluate(s);
	require(!any(rows,CHECK_BAD) && result(rows,"VM-029").outcome==CHECK_OBSERVATION &&
		result(rows,"VM-046").outcome==CHECK_OBSERVATION,"network and historical clues cannot fail VM score");
	s={}; const auto tcg=load("measured-boot.bin"); s.measured_boot=Sample<Bytes>::ok(tcg);
	require(result(evaluate(s),"VM-040").outcome==CHECK_OBSERVATION,"captured measured-boot ACPI events recognized");
	for (auto n:{0u,31u,60u,100u,unsigned(tcg.size()-1)}) {
		s.measured_boot.value.assign(tcg.begin(),tcg.begin()+n);
		require(result(evaluate(s),"VM-040").outcome==CHECK_ERROR,"truncated measured-boot data is an error");
	}
	s.measured_boot.value=tcg; put32(s.measured_boot.value,56,0xffffffff);
	require(result(evaluate(s),"VM-040").outcome==CHECK_ERROR,"oversized digest list rejected");

	// Seeded malformed buffers exercise lengths, terminators and checksums under ASan/UBSan.
	std::mt19937 random(0x20261016);
	for(unsigned i=0;i<2000;++i) {
		Bytes b(random()%2048); for(auto& x:b) x=std::uint8_t(random());
		Snapshot fuzz; fuzz.smbios=Sample<Bytes>::ok(b); evaluate(fuzz);
		fuzz={}; fuzz.acpi=decltype(fuzz.acpi)::ok({b}); evaluate(fuzz);
		fuzz={}; fuzz.measured_boot=Sample<Bytes>::ok(b); evaluate(fuzz);
		nvme_payload(b,4096,1);
	}
	stats_init();
	for(int outcome:{CHECK_GOOD,CHECK_BAD,CHECK_OBSERVATION,CHECK_ERROR}) stats_record(CAT_QEMU,outcome);
	stats_print();
	std::cout << "Assertions passed: " << assertions << '\n';
}
