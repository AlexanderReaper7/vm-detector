#include "Adversary.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace adversary {
namespace {
std::uint32_t le32(const Bytes& b, std::size_t p)
{
	return std::uint32_t(b[p]) | std::uint32_t(b[p+1]) << 8 |
		std::uint32_t(b[p+2]) << 16 | std::uint32_t(b[p+3]) << 24;
}
std::uint64_t le64(const Bytes& b, std::size_t p)
{
	return std::uint64_t(le32(b,p)) | std::uint64_t(le32(b,p+4)) << 32;
}
std::uint16_t le16(const Bytes& b, std::size_t p)
{
	return std::uint16_t(b[p] | std::uint16_t(b[p+1]) << 8);
}
std::string text(const Bytes& b, std::size_t p, std::size_t length)
{
	std::string s;
	for (std::size_t i = p; i < p + length && b[i]; ++i)
		s += b[i] >= 32 && b[i] < 127 ? char(b[i]) : '?';
	while (!s.empty() && s.back() == ' ') s.pop_back();
	return s;
}
std::string upper(std::string s)
{
	for (char& c : s) c = char(std::toupper(static_cast<unsigned char>(c)));
	return s;
}
bool has(const std::string& s, const std::string& part)
{
	return upper(s).find(upper(part)) != std::string::npos;
}
bool starts(const std::string& s, const std::string& prefix)
{
	return upper(s).rfind(upper(prefix),0)==0;
}
bool qemu_machine(const std::string& s)
{
	std::size_t start=0;
	if (s.rfind("pc-q35-",0)==0) start=7;
	else if (s.rfind("pc-i440fx-",0)==0) start=10;
	else return false;
	bool digit=false; unsigned dots=0;
	for (std::size_t p=start;p<s.size();++p) {
		if (s[p]>='0' && s[p]<='9') digit=true;
		else if (s[p]=='.' && digit) { ++dots; digit=false; }
		else return false;
	}
	return digit && dots>=1 && dots<=2;
}
std::string hex(std::uint32_t value)
{
	std::ostringstream s; s << "0x" << std::hex << value; return s.str();
}
std::string join(const std::vector<std::string>& rows)
{
	std::string s;
	for (const auto& row : rows) {
		if (!s.empty()) s += "; ";
		s += row;
	}
	return s;
}
void add(std::vector<Result>& out, const char* id, const char* title,
	bool match, CheckOutcome matched, const std::string& evidence)
{
	out.push_back({id, title, match ? matched : CHECK_GOOD, match ? evidence : std::string{}});
}
template<class T> bool ready(std::vector<Result>& out, const Sample<T>& sample,
	const char* id, const char* title)
{
	if (sample.state == ReadState::Error)
		out.push_back({id, title, CHECK_ERROR, sample.reason});
	return sample.state == ReadState::Ok;
}
struct Structure {
	Bytes data;
	std::vector<std::string> strings;
	std::string string_at(std::size_t offset) const {
		if (offset >= data.size() || data[offset] == 0 || data[offset] > strings.size()) return {};
		return strings[data[offset]-1];
	}
};
Sample<std::vector<Structure>> parse_smbios(const Bytes& bytes)
{
	using Parsed = Sample<std::vector<Structure>>;
	if (bytes.size() < 8 || le32(bytes, 4) != bytes.size() - 8)
		return Parsed::error("RSMB length does not match returned bytes");
	std::vector<Structure> tables;
	std::size_t p = 8;
	while (p < bytes.size()) {
		if (bytes.size() - p < 4 || bytes[p+1] < 4 || bytes[p+1] > bytes.size() - p)
			return Parsed::error("truncated SMBIOS structure");
		std::size_t end = p + bytes[p+1];
		Structure table{Bytes(bytes.begin()+p, bytes.begin()+end), {}};
		const unsigned type=table.data[0], length=table.data.size();
		unsigned minimum=4;
		switch (type) {
		case 0: minimum=0x12; break; case 2: minimum=8; break; case 3: minimum=9; break;
		case 4: minimum=0x1a; break; case 7: minimum=0x0f; break; case 16: minimum=0x0f; break; case 17: minimum=0x15; break;
		case 19: minimum=0x0f; break; case 41: minimum=0x0b; break;
		}
		if (length<minimum) return Parsed::error("SMBIOS record shorter than its required fields");
		std::size_t terminator = end;
		while (terminator + 1 < bytes.size() && (bytes[terminator] || bytes[terminator+1])) ++terminator;
		if (terminator + 1 >= bytes.size()) return Parsed::error("unterminated SMBIOS string set");
		while (end < terminator) {
			std::size_t next = end;
			while (next < terminator && bytes[next]) ++next;
			table.strings.push_back(text(bytes, end, next-end));
			end = next + 1;
		}
		unsigned string_field=0;
		switch (type) {
		case 2: case 41: string_field=4; break;
		case 4: case 17: string_field=16; break;
		}
		if (string_field && table.data[string_field]>table.strings.size())
			return Parsed::error("SMBIOS string index is outside its string set");
		const bool last = table.data[0] == 127;
		tables.push_back(std::move(table));
		p = terminator + 2;
		if (last) {
			if (p != bytes.size()) return Parsed::error("data after SMBIOS end marker");
			return Parsed::ok(std::move(tables));
		}
	}
	return Parsed::error("SMBIOS end marker missing");
}
std::array<std::uint32_t, 4> leaf(const Cpu& cpu, std::uint32_t number)
{
	auto it = cpu.leaves.find(number);
	return it == cpu.leaves.end() ? std::array<std::uint32_t,4>{} : it->second;
}
}

bool valid_acpi(const Bytes& data, std::string& error)
{
	if (data.size() < 36 || le32(data, 4) != data.size()) {
		error = "ACPI header length does not match returned bytes"; return false;
	}
	unsigned sum = 0;
	for (auto b : data) sum += b;
	if (sum & 255) { error = "ACPI checksum mismatch"; return false; }
	return true;
}

Sample<Bytes> nvme_payload(const Bytes& response, std::size_t requested, std::uint32_t type)
{
	// STORAGE_PROTOCOL_DATA_DESCRIPTOR: 8-byte header, followed by the protocol data.
	// ProtocolDataOffset is relative to that protocol structure, NOT to the response.
	if (response.size() < 48 || le32(response, 0) != 48 || le32(response, 4) != 48 ||
		le32(response, 8) != 3 || le32(response, 12) != type)
		return Sample<Bytes>::error("invalid NVMe protocol descriptor");
	const std::size_t offset = le32(response, 24), length = le32(response, 28);
	if (offset < 40 || offset > response.size()-8 || length < requested ||
		length > response.size()-8-offset)
		return Sample<Bytes>::error("NVMe payload is truncated or outside returned bytes");
	return Sample<Bytes>::ok(Bytes(response.begin()+8+offset, response.begin()+8+offset+requested));
}

std::vector<Result> evaluate(const Snapshot& s)
{
	std::vector<Result> out;
	if (ready(out, s.devices, "devices", "Present device identities")) {
		std::vector<std::string> fwcfg, vga, subsystem, q35, nic, usb;
		unsigned hotplug = 0;
		for (const auto& id : s.devices.value) {
			if (starts(id, "ACPI\\QEMU0002\\") || upper(id) == "ACPI\\QEMU0002") fwcfg.push_back(id);
			if (starts(id, "PCI\\VEN_1234&DEV_1111&")) vga.push_back(id);
			const auto sub=upper(id).find("&SUBSYS_11001AF4");
			if (starts(id, "PCI\\") && sub!=std::string::npos && (sub+16==id.size() ||
				id[sub+16]=='&' || id[sub+16]=='\\')) subsystem.push_back(id);
			if (starts(id, "PCI\\VEN_8086&DEV_29C0&") || starts(id, "PCI\\VEN_8086&DEV_2918&")) q35.push_back(id);
			if (starts(id, "PCI\\VEN_8086&DEV_10D3&")) nic.push_back(id);
			if (starts(id, "PCI\\VEN_1033&DEV_0194&")) usb.push_back(id);
			if (starts(id, "ACPI\\PNP0A06\\")) {
				if (has(id,"CPU_HOTPLUG_RESOURCES")) hotplug|=1;
				if (has(id,"PCI_HOTPLUG_RESOURCES")) hotplug|=2;
				if (has(id,"SMI_RESOURCES")) hotplug|=4;
				if (has(id,"GPE0_RESOURCES")) hotplug|=8;
			}
		}
		add(out,"VM-001","QEMU fw_cfg device ID",!fwcfg.empty(),CHECK_BAD,join(fwcfg));
		add(out,"VM-002","QEMU standard VGA PCI identity",!vga.empty(),CHECK_BAD,join(vga));
		add(out,"VM-003/011","QEMU-assigned PCI subsystem identity",!subsystem.empty(),CHECK_BAD,join(subsystem));
		add(out,"VM-009","QEMU hotplug resource device identifiers",hotplug == 15,CHECK_OBSERVATION,"resource identifier mask="+hex(hotplug));
		add(out,"VM-007","Intel 82574L device (also exists physically)",!nic.empty(),CHECK_OBSERVATION,join(nic));
		add(out,"VM-008","NEC xHCI device (also exists physically)",!usb.empty(),CHECK_OBSERVATION,join(usb));
		bool ps2_keyboard=false, ps2_mouse=false;
		for (const auto& id:s.devices.value) {
			ps2_keyboard|=starts(id,"ACPI\\PNP0303\\");
			ps2_mouse|=starts(id,"ACPI\\PNP0F13\\");
		}
		if (s.cpu.state==ReadState::Ok && s.cpu.value.vendor=="AuthenticAMD" && has(s.cpu.value.brand,"Ryzen") &&
			ready(out,s.pci_buses,"OPUS-017","PCI bus-number inventory") && !s.pci_buses.value.empty()) {
			bool amd=false;
			for (const auto& id:s.devices.value) amd|=starts(id,"PCI\\VEN_1022&");
			add(out,"OPUS-017","Ryzen PCI inventory confined to bus zero without AMD devices",
				!amd && std::all_of(s.pci_buses.value.begin(),s.pci_buses.value.end(),[](std::uint32_t b){return !b;}),
				CHECK_OBSERVATION,"PCI functions="+std::to_string(s.pci_buses.value.size())+"; topology clue, not a physical impossibility claim");
		}
		add(out,"OPUS-013","Present ACPI PS/2 keyboard and mouse pair",ps2_keyboard && ps2_mouse,
			CHECK_OBSERVATION,"PNP0303 and PNP0F13; physical boards may also expose legacy controllers");
		if (s.cpu.state == ReadState::Ok && s.cpu.value.vendor == "AuthenticAMD")
			add(out,"VM-004/012","AMD CPU with Q35/ICH9 host chipset",!q35.empty(),CHECK_OBSERVATION,join(q35));
	}

	if (ready(out,s.hid,"CODEX-004","Present HID interface enumeration")) {
		std::vector<std::string> matched;
		bool queried=false, failed=false;
		for (const auto& hid:s.hid.value) for (const auto& entry:hid.indexed_strings) {
			if (entry.second.state==ReadState::Error) failed=true;
			if (!ready(out,entry.second,"CODEX-004",("HID indexed string "+std::to_string(entry.first)).c_str())) continue;
			queried=true;
			const auto& value=entry.second.value;
			if (upper(value)=="QEMU" || starts(value,"QEMU "))
				matched.push_back(hid.path+" index="+std::to_string(entry.first)+" value="+value);
		}
		if (queried && (!failed || !matched.empty()))
			add(out,"CODEX-004","HID indexed descriptor explicitly names QEMU",!matched.empty(),CHECK_BAD,join(matched));
	}

	auto smbios = s.smbios.state == ReadState::Ok ? parse_smbios(s.smbios.value) :
		Sample<std::vector<Structure>>{s.smbios.state, {}, s.smbios.reason};
	if (ready(out, smbios, "smbios", "SMBIOS structure parsing")) {
		std::vector<std::string> versions, memory, boards, onboard;
		unsigned other = 0, handles = 0, structures = 0, processors = 0;
		std::uint32_t l3_kib = 0;
		unsigned l3_count = 0;
		unsigned memory_slots=0, populated=0;
		std::uint64_t memory_max=0, installed=0;
		bool memory_known=true, array_present=false;
		bool lowmem = false;
		for (const auto& table : smbios.value) {
			const auto& b = table.data;
			++structures;
			if (le16(b,2) == unsigned(b[0])*256 && b[0] != 0) ++handles;
			if (b[0] == 2) boards.push_back(table.string_at(4));
			if (b[0] == 3 && b.size() > 5 && (b[5]&127) == 1) ++other;
			if (b[0] == 4) { ++processors; versions.push_back(table.string_at(16)); }
			if (b[0] == 7 && b.size() >= 11 && (le16(b,5)&7) == 2) {
				++l3_count;
				const auto installed = le16(b,9);
				if (installed != 0xffff) l3_kib = (installed&0x7fff) * ((installed&0x8000) ? 64u : 1u);
			}
			if (b[0] == 17 && b.size() >= 23 && le16(b,12) != 0 &&
				(b[18] == 7 || le16(b,21) == 0))
				memory.push_back(table.string_at(16)+" type="+std::to_string(b[18])+" speed="+std::to_string(le16(b,21)));
			if (b[0] == 16) {
				array_present=true;
				memory_slots+=le16(b,13);
				if (le32(b,7)!=0x80000000) memory_max+=std::uint64_t(le32(b,7))*1024;
				else if (b.size()>=23) memory_max+=le64(b,15);
				else memory_known=false;
			}
			if (b[0] == 17) {
				const auto size=le16(b,12);
				if (size==0xffff) memory_known=false;
				else if (size==0x7fff) {
					if (b.size()>=32) { installed+=std::uint64_t(le32(b,28)&0x7fffffff)*1024*1024; ++populated; }
					else memory_known=false;
				} else if (size) { installed+=std::uint64_t(size&0x7fff)*((size&0x8000)?1024:1024*1024); ++populated; }
			}
			if (b[0] == 19 && b.size() >= 15 && le32(b,4) == 0 && le32(b,8) == 0x1fffff) lowmem = true;
			if (b[0] == 41 && b.size() >= 11 && b[5] == 0x87) onboard.push_back(table.string_at(4));
		}
		if (memory_known && array_present && installed)
			add(out,"OPUS-010","Single-slot memory array maximum equals installed RAM",
				memory_slots==1 && populated==1 && memory_max==installed,CHECK_OBSERVATION,
				"slots="+std::to_string(memory_slots)+" populated="+std::to_string(populated)+
				" maximum bytes="+std::to_string(memory_max)+" installed bytes="+std::to_string(installed));
		add(out,"OPUS-016","Legacy SMBIOS entry point and small structure inventory",
			s.smbios.value[1]<3 && structures<=48,CHECK_OBSERVATION,
			"SMBIOS="+std::to_string(s.smbios.value[1])+"."+std::to_string(s.smbios.value[2])+
			" structures="+std::to_string(structures));
		bool machine = false;
		for (const auto& v : versions) if (qemu_machine(v)) machine = true;
		add(out,"VM-014","SMBIOS processor names a QEMU machine",machine,CHECK_BAD,join(versions));
		add(out,"VM-006","SMBIOS chassis classified as Other",other != 0,CHECK_OBSERVATION,"Other chassis records="+std::to_string(other));
		add(out,"VM-015","SMBIOS handles follow QEMU numbering",handles >= 5,CHECK_OBSERVATION,"type*256 handles="+std::to_string(handles)+" structures="+std::to_string(structures));
		add(out,"VM-016","Populated RAM has generic type or zero speed",!memory.empty(),CHECK_OBSERVATION,join(memory));
		add(out,"VM-034","SMBIOS low RAM ends exactly at 2 GiB",lowmem,CHECK_OBSERVATION,"memory-map records only; not a physical-memory measurement");
		if (s.devices.state == ReadState::Ok) {
			bool audio = false;
			for (const auto& id : s.devices.value) if (has(id,"HDAUDIO\\")) audio = true;
			add(out,"VM-038","Enabled ALC1220 inventory without present HD Audio",has(join(onboard),"ALC1220") && !audio,
				CHECK_OBSERVATION,join(onboard)+"; present HDAUDIO="+(audio?"yes":"no"));
		}
		if (s.cpu.state == ReadState::Ok && s.cpu.value.vendor == "AuthenticAMD" &&
			s.cpu.value.max_extended >= 0x80000006 && processors == 1 && l3_count == 1 && l3_kib) {
			const auto cpu_l3 = ((leaf(s.cpu.value,0x80000006)[3] >> 18)&0x3fff)*512u;
			if (cpu_l3) add(out,"VM-037","SMBIOS and CPU L3 cache descriptions disagree",cpu_l3 != l3_kib,
				CHECK_OBSERVATION,"SMBIOS L3 KiB="+std::to_string(l3_kib)+" CPUID L3 KiB="+std::to_string(cpu_l3));
		}
		if (s.acpi.state == ReadState::Ok && (has(join(boards),"MSI") || has(join(boards),"MICRO-STAR"))) {
			bool asus = false;
			for (const auto& b : s.acpi.value) {
				std::string error;
				if (valid_acpi(b,error) && text(b,10,6) == "ASUS") asus = true;
			}
			add(out,"VM-013","MSI inventory with ASUS ACPI OEM identity",asus,CHECK_OBSERVATION,join(boards));
		}
	}
	if (ready(out,s.bios_versions,"VM-005","Windows BIOS version strings"))
		add(out,"VM-005","EDK II BIOS inventory (also used physically)",has(join(s.bios_versions.value),"EDK II"),
			CHECK_OBSERVATION,join(s.bios_versions.value));

	if (ready(out,s.acpi,"acpi","ACPI table collection")) {
		bool marker=false, edk=false, constant=false, hpet=false, madt=false;
		bool fwcfg_ports=false, cpu_hotplug=false, ivrs=false, crat=false, cdit=false;
		std::string invalid;
		std::vector<std::string> names;
		for (const auto& b : s.acpi.value) {
			if (!valid_acpi(b,invalid)) break;
			const auto sig = text(b,0,4);
			ivrs|=sig=="IVRS"; crat|=sig=="CRAT"; cdit|=sig=="CDIT";
			names.push_back(sig+"/"+text(b,10,6)+"/"+text(b,16,8));
			// Only executable ACPI tables are searched, not arbitrary memory or logs.
			if (sig == "DSDT" || sig == "SSDT") {
				const std::string aml(b.begin()+36,b.end());
				// Match resource/operation-region byte templates, not a general AML parse.
				const std::string ports("\x47\x01\x10\x05\x10\x05\x01\x0c",8);
				const std::string hotplug("\x5b\x80PRST\x01\x0b\xd8\x0c",10);
				fwcfg_ports|=aml.find(ports)!=std::string::npos;
				cpu_hotplug|=aml.find(hotplug)!=std::string::npos;
				if (aml.find("QEMU0002") != std::string::npos) marker=true;
				const std::string method("\x14\x0a_TMP\0\xa4\x0b",9);
				const auto p=aml.find(method);
				if (p != std::string::npos && aml.size()-p >= 11) constant=true;
			}
			if (text(b,10,6)=="INTEL" && text(b,16,8)=="EDK2") edk=true;
			if (sig=="HPET" && b.size()>=40 && le32(b,36)==0x8086a201) hpet=true;
			if (sig=="APIC" && b.size()>=44) {
				unsigned ioapics=0, isos=0;
				std::size_t p=44;
				while (p<b.size()) {
					if (b.size()-p<2 || b[p+1]<2 || b[p+1]>b.size()-p) { invalid="invalid MADT subtable length"; break; }
					if (b[p]==1 && b[p+1]>=12) ++ioapics;
					if (b[p]==2 && b[p+1]>=10 && le16(b,p+8)==13 &&
						(b[p+3]==5 || b[p+3]==9 || b[p+3]==10 || b[p+3]==11)) ++isos;
					p+=b[p+1];
				}
				madt=ioapics==1 && isos==4;
			}
		}
		if (!invalid.empty()) out.push_back({"acpi-parse","ACPI table validation",CHECK_ERROR,invalid});
		else {
			add(out,"CODEX-003","ACPI declarations match fw_cfg and CPU-hotplug port layout",
				fwcfg_ports && cpu_hotplug,CHECK_OBSERVATION,"AML resource templates: 0x510 length 12 and PRST I/O 0xcd8; no live port query");
			if (s.cpu.state==ReadState::Ok && s.cpu.value.vendor=="AuthenticAMD" && has(s.cpu.value.brand,"Ryzen"))
				add(out,"OPUS-009","Ryzen ACPI set lacks IVRS, CRAT and CDIT",!ivrs && !crat && !cdit,
					CHECK_OBSERVATION,join(names)+"; firmware configuration can also omit these tables");
			add(out,"VM-017","QEMU identity inside ACPI executable tables",marker,CHECK_BAD,"QEMU0002 in validated DSDT/SSDT");
			add(out,"OPUS-008","ACPI header names INTEL / EDK2",edk,CHECK_OBSERVATION,join(names));
			add(out,"VM-018","Small or EDK2-labelled ACPI table set",s.acpi.value.size()<=8 || edk,CHECK_OBSERVATION,join(names));
			add(out,"VM-033","HPET has QEMU default block identity",hpet,CHECK_OBSERVATION,"EventTimerBlockID=0x8086a201");
			add(out,"VM-036","MADT matches QEMU interrupt-routing pattern",madt,CHECK_OBSERVATION,"one IOAPIC and four level/high overrides for IRQ 5/9/10/11");
			add(out,"VM-045","ACPI _TMP method returns a literal constant",constant,CHECK_OBSERVATION,"matched AML Method(_TMP,0){Return(WordConst)}; no claim about sampled temperature");
		}
	}

	if (ready(out,s.cpu,"cpu","CPU identification")) {
		const auto& c=s.cpu.value;
		if (c.vendor=="AuthenticAMD") {
			const auto one=leaf(c,1), ext=leaf(c,0x80000001), cache=leaf(c,0x80000006);
			if (c.max_extended>=0x80000008)
				add(out,"VM-043","AMD virtual-only SSBD feature",(leaf(c,0x80000008)[1]&(1u<<25))!=0,CHECK_BAD,
					"CPUID.80000008:EBX="+hex(leaf(c,0x80000008)[1]));
			if (c.max_extended>=0x8000000a && (ext[2]&(1u<<2)))
				add(out,"VM-020","SVM ASID count matches QEMU default",leaf(c,0x8000000a)[1]==16,CHECK_OBSERVATION,
					"ASIDs="+std::to_string(leaf(c,0x8000000a)[1]));
			if (c.max_extended>=0x80000006)
				add(out,"VM-019","Modern AMD CPU with QEMU legacy cache profile",
					has(c.brand,"Ryzen") && (cache[2]>>16)==512 && ((cache[3]>>18)&0x3fff)==32,
					CHECK_OBSERVATION,c.brand+"; CPUID.80000006 ECX="+hex(cache[2])+" EDX="+hex(cache[3]));
			if (c.max_basic>=7)
				add(out,"VM-021","AMD leaf 7 advertises IBRS, STIBP and SSBD",(leaf(c,7)[3]&0x8c000000)==0x8c000000,
					CHECK_OBSERVATION,"CPUID.7:EDX="+hex(leaf(c,7)[3]));
			if (c.max_basic>=6 && c.max_extended>=0x80000007)
				add(out,"VM-022","Sparse AMD power-management feature profile",!(one[2]&8) && leaf(c,6)[2]==0 &&
					leaf(c,0x80000007)[3]==256,CHECK_OBSERVATION,"MONITOR absent, leaf6 ECX=0, extended power EDX=0x100");
			if (c.max_extended>=0x80000007 && has(c.brand,"Ryzen") && (has(c.brand,"9600X") || has(c.brand,"9700X")))
				add(out,"OPUS-006","Ryzen 9600X/9700X omits CPB capability",!(leaf(c,0x80000007)[3]&(1u<<9)),
					CHECK_OBSERVATION,"CPUID.80000007:EDX="+hex(leaf(c,0x80000007)[3])+"; PCID/MONITOR absence is not scored");
			const unsigned family=((one[0]>>8)&15)+(((one[0]>>8)&15)==15 ? (one[0]>>20)&255 : 0);
			if (family>=0x1a && c.max_extended>=0x8000001f)
				add(out,"OPUS-015","Recent AMD memory-encryption leaf is all zero",
					leaf(c,0x8000001f)==std::array<std::uint32_t,4>{},CHECK_OBSERVATION,
					"CPUID.8000001F is supported by range; firmware may hide encryption capabilities");
			if (family>=0x1a)
				add(out,"VM-047","Recent AMD family has limited extended leaves",c.max_extended<0x80000026,
					CHECK_OBSERVATION,"family="+hex(family)+" max extended="+hex(c.max_extended));
		}
	}

	if (ready(out,s.disks,"nvme","NVMe disk enumeration")) for (const auto& d : s.disks.value) {
		if (ready(out,d.identify,"VM-024","NVMe controller Identify")) {
			const auto& b=d.identify.value;
			if (b.size()!=4096) { out.push_back({"VM-024","NVMe Identify length",CHECK_ERROR,d.path}); continue; }
			const auto nqn=text(b,768,256), model=text(b,24,40);
			add(out,"CODEX-002-OUI","NVMe IEEE field matches QEMU default",
				b[73]==0 && b[74]==0x54 && b[75]==0x52,CHECK_OBSERVATION,
				d.path+"; wire IEEE bytes="+hex(b[73])+","+hex(b[74])+","+hex(b[75]));
			if (le32(b,80)==0x00010400 && (le16(b,256)&8) &&
				ready(out,d.namespace_identify,"CODEX-002-CAP","NVMe namespace Identify")) {
				const auto& ns=d.namespace_identify.value;
				if (ns.size()!=4096) out.push_back({"CODEX-002-CAP","NVMe namespace Identify length",CHECK_ERROR,d.path});
				else {
					const unsigned format=ns[26]&15;
					const auto size=le64(ns,0), capacity=le64(ns,8), used=le64(ns,16);
					if (ns[25]>15 || format>ns[25] || ns[130+format*4]<9 || ns[130+format*4]>63 ||
						capacity>size || used>capacity)
						out.push_back({"CODEX-002-CAP","NVMe namespace Identify validation",CHECK_ERROR,d.path});
					else {
						const bool zero=std::all_of(b.begin()+280,b.begin()+296,[](std::uint8_t x){return !x;});
						add(out,"CODEX-002-CAP","NVMe 1.4 advertises namespace management with zero total capacity",
							zero && capacity>0 && !(ns[24]&1),CHECK_BAD,
							d.path+"; OACS="+hex(le16(b,256))+" TNVMCAP=0; non-thin NCAP="+
							std::to_string(capacity)+" LBADS="+std::to_string(ns[130+format*4])+
							"; NVMe 1.4 section 5.15.2.2 Figure 247");
					}
				}
			}
			add(out,"VM-024","NVMe controller names QEMU",nqn.rfind("nqn.2019-08.org.qemu:",0)==0,
				CHECK_BAD,d.path+"; model="+model+"; SUBNQN="+nqn);
			if (has(model,"2TB") && ready(out,d.capacity,"VM-010","NVMe disk length"))
				add(out,"VM-010","2 TB model exposes less than 1.9 TB",d.capacity.value<1900000000000ull,
					CHECK_OBSERVATION,d.path+"; bytes="+std::to_string(d.capacity.value)+"; smaller namespaces can also exist physically");
			if (ready(out,d.firmware,"VM-026","NVMe firmware-slot log")) {
				const auto& f=d.firmware.value;
				if (f.size()!=512 || !(f[0]&7)) out.push_back({"VM-026","NVMe active firmware slot",CHECK_ERROR,"missing or invalid active slot"});
				else {
					const auto active=text(f,8+((f[0]&7)-1)*8,8), identify=text(b,64,8);
					add(out,"VM-026","NVMe active-slot and Identify revisions disagree",!active.empty() && !identify.empty() && active!=identify,
						CHECK_OBSERVATION,d.path+"; Identify="+identify+"; active slot="+active);
				}
			}
		}
		if (ready(out,d.smart,"VM-025","NVMe SMART log")) {
			const auto& b=d.smart.value;
			if (b.size()!=512) out.push_back({"VM-025","NVMe SMART length",CHECK_ERROR,d.path});
			else {
				const bool zero=std::all_of(b.begin()+112,b.begin()+144,[](std::uint8_t x){return x==0;});
				add(out,"VM-025","NVMe SMART matches QEMU default values",le16(b,1)==323 && b[3]==0 && b[4]==0,
					CHECK_OBSERVATION,d.path+"; temp K="+std::to_string(le16(b,1))+" spare %="+std::to_string(b[3])+"; zero cycle/hour counters="+(zero?"yes":"no"));
			}
		}
	}
	if (ready(out,s.tpm,"VM-027","TPM manufacturer and vendor properties"))
		add(out,"VM-027","TPM identifies as software TPM",has(s.tpm.value.vendor,"SW   TPM"),CHECK_BAD,
			"manufacturer="+s.tpm.value.manufacturer+"; vendor="+s.tpm.value.vendor);
	if (ready(out,s.certificates,"VM-039","TPM endorsement certificate identities")) {
		bool match=false; std::vector<std::string> identities;
		for (const auto& c:s.certificates.value) {
			if (upper(c.issuer)=="SWTPM-LOCALCA") match=true;
			identities.push_back("issuer="+c.issuer+" subject="+c.subject);
		}
		add(out,"VM-039","TPM endorsement issuer names swtpm",match,CHECK_BAD,join(identities));
	}
	if (ready(out,s.uefi.boot_order_marker,"VM-031","OVMF VMMBootOrder0000 variable"))
		add(out,"VM-031","OVMF-specific boot-order variable exists",!s.uefi.boot_order_marker.value.empty(),CHECK_BAD,
			"VMMBootOrder0000 under {668f4529-63d0-4bb5-b65d-6fbb9d36a44a}");
	if (ready(out,s.uefi.languages,"VM-032","UEFI platform language list"))
		add(out,"VM-032","UEFI language list matches stock OVMF",text(s.uefi.languages.value,0,s.uefi.languages.value.size())=="en;fr;en-US;fr-FR",
			CHECK_OBSERVATION,text(s.uefi.languages.value,0,s.uefi.languages.value.size()));
	if (ready(out,s.uefi.boot_descriptions,"VM-028","Firmware boot menu descriptions"))
		add(out,"VM-028","Firmware boot menu names EDK2 application",has(join(s.uefi.boot_descriptions.value),"BootManagerMenuApp"),
			CHECK_OBSERVATION,join(s.uefi.boot_descriptions.value));
	if (ready(out,s.storage_history,"VM-046","Storage event device identities"))
		add(out,"VM-046","Historical storage events name QEMU",!s.storage_history.value.empty(),CHECK_OBSERVATION,
			join(s.storage_history.value));
	if (ready(out,s.gateways,"VM-029","Cached default-gateway neighbours"))
		add(out,"VM-029","Gateway MAC matches libvirt default prefix",has(join(s.gateways.value),"52:54:00"),CHECK_OBSERVATION,join(s.gateways.value));
	if (ready(out,s.pci_links,"VM-041","PCI Express device properties"))
		add(out,"VM-041","Device classified as PCI Express treated as PCI",!s.pci_links.value.empty(),CHECK_OBSERVATION,join(s.pci_links.value));
	if (ready(out,s.processor_power,"VM-035","Current-boot processor power event"))
		add(out,"VM-035","Processor exposes no performance-state implementation",s.processor_power.value=="0",
			CHECK_OBSERVATION,"Kernel-Processor-Power event55 PerformanceImplementation="+s.processor_power.value);
	if (ready(out,s.measured_boot,"VM-040","Current TPM measured-boot log")) {
		const auto& b=s.measured_boot.value;
		std::map<unsigned,unsigned> sizes;
		std::string failure;
		std::size_t p=0;
		if (b.size()<61 || le32(b,28)>b.size()-32 || le32(b,28)<29 ||
			std::memcmp(b.data()+32,"Spec ID Event03",15)!=0) failure="invalid TCG2 Spec ID event";
		else {
			const std::size_t length=le32(b,28), count=le32(b,56);
			if (!count || count>32 || count>(length-29)/4) failure="invalid TCG2 digest-size list";
			else {
				for (std::size_t i=0;i<count;++i) {
					const unsigned alg=le16(b,60+i*4), size=le16(b,62+i*4);
					if (!size || size>128 || sizes.count(alg)) { failure="invalid TCG2 digest size"; break; }
					sizes[alg]=size;
				}
				p=32+length;
			}
		}
		unsigned acpi_data=0;
		while (failure.empty() && p<b.size()) {
			if (b.size()-p<12) { failure="truncated TCG2 event header"; break; }
			const auto type=le32(b,p+4), count=le32(b,p+8);
			if (!count || count>sizes.size()) { failure="invalid TCG2 event digest count"; break; }
			p+=12;
			for (unsigned i=0;i<count;++i) {
				if (b.size()-p<2) { failure="truncated TCG2 digest"; break; }
				auto it=sizes.find(le16(b,p));
				if (it==sizes.end() || it->second>b.size()-p-2) { failure="unknown or truncated TCG2 digest"; break; }
				p+=2+it->second;
			}
			if (!failure.empty()) break;
			if (b.size()-p<4) { failure="truncated TCG2 event size"; break; }
			const auto length=le32(b,p); p+=4;
			if (length>b.size()-p) { failure="TCG2 event payload exceeds log"; break; }
			if (type==10 && length==9 && std::memcmp(b.data()+p,"ACPI DATA",9)==0) ++acpi_data;
			p+=length;
		}
		if (!failure.empty()) out.push_back({"VM-040","TCG2 measured-boot log validation",CHECK_ERROR,failure});
		else add(out,"VM-040","Measured boot includes ACPI DATA configuration events",acpi_data>=1,
			CHECK_OBSERVATION,"EV_PLATFORM_CONFIG_FLAGS ACPI DATA events="+std::to_string(acpi_data));
	}
	return out;
}
}
