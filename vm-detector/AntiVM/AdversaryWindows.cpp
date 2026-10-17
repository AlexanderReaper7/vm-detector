#include "pch.h"
#include "Adversary.h"
#include "AdversaryWindows.h"
#include <devpkey.h>
#include <hidsdi.h>

#pragma comment(lib,"hid.lib")
#include <pciprop.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <tbs.h>
#include <winevt.h>
#include <netioapi.h>

#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"tbs.lib")
#pragma comment(lib,"wevtapi.lib")

namespace {
using namespace adversary;
constexpr DWORD limit = 16*1024*1024;
std::string error(const char* operation, DWORD code = GetLastError())
{
	return std::string(operation)+" error="+std::to_string(code);
}
std::string narrow(const std::wstring& s)
{
	if (s.empty()) return {};
	int n=WideCharToMultiByte(CP_UTF8,0,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);
	std::string result(n,'\0');
	WideCharToMultiByte(CP_UTF8,0,s.data(),int(s.size()),result.data(),n,nullptr,nullptr);
	return result;
}
std::wstring wide(const std::string& s)
{
	if (s.empty()) return {};
	int n=MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),nullptr,0);
	std::wstring result(n,L'\0');
	MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),result.data(),n);
	return result;
}
Sample<Bytes> firmware(DWORD provider, DWORD table)
{
	UINT size=GetSystemFirmwareTable(provider,table,nullptr,0);
	if (!size || size>limit) return Sample<Bytes>::error(error("GetSystemFirmwareTable size"));
	Bytes bytes(size);
	UINT got=GetSystemFirmwareTable(provider,table,bytes.data(),size);
	if (got!=size) return Sample<Bytes>::error("firmware table changed size or could not be read");
	return Sample<Bytes>::ok(std::move(bytes));
}
Sample<std::vector<Bytes>> acpi_tables()
{
	using S=Sample<std::vector<Bytes>>;
	UINT size=EnumSystemFirmwareTables('ACPI',nullptr,0);
	if (!size || size>4096 || size%4) return S::error(error("EnumSystemFirmwareTables size"));
	std::vector<DWORD> ids(size/4);
	if (EnumSystemFirmwareTables('ACPI',ids.data(),size)!=size) return S::error(error("EnumSystemFirmwareTables"));
	std::vector<Bytes> tables;
	std::size_t total=0;
	// On this Windows system DSDT is retrievable by ID but absent from enumeration.
	if (std::find(ids.begin(),ids.end(),DWORD('TDSD'))==ids.end()) ids.push_back('TDSD');
	auto unique=ids; std::sort(unique.begin(),unique.end());
	if (std::adjacent_find(unique.begin(),unique.end())!=unique.end())
		return S::error("ACPI signatures repeat; Windows can retrieve only the first table per signature");
	for (DWORD id:ids) {
		auto table=firmware('ACPI',id);
		if (table.state!=ReadState::Ok) return S::error(table.reason);
		total+=table.value.size();
		if (total>limit) return S::error("ACPI collection exceeds 16 MiB limit");
		tables.push_back(std::move(table.value));
	}
	return S::ok(std::move(tables));
}
Sample<std::vector<std::string>> bios_versions()
{
	using S=Sample<std::vector<std::string>>;
	DWORD size=0,type=0;
	const wchar_t* key=L"HARDWARE\\DESCRIPTION\\System";
	const DWORD flags=RRF_RT_REG_MULTI_SZ|RRF_RT_REG_SZ;
	LSTATUS status=RegGetValueW(HKEY_LOCAL_MACHINE,key,L"SystemBiosVersion",flags,&type,nullptr,&size);
	if (status==ERROR_FILE_NOT_FOUND) return {};
	if (status!=ERROR_SUCCESS || !size || size>65536 || size%sizeof(wchar_t)) return S::error(error("BIOS version registry size",status));
	std::vector<wchar_t> buffer(size/sizeof(wchar_t));
	status=RegGetValueW(HKEY_LOCAL_MACHINE,key,L"SystemBiosVersion",flags,&type,buffer.data(),&size);
	if (status!=ERROR_SUCCESS || size>buffer.size()*sizeof(wchar_t) || size%sizeof(wchar_t))
		return S::error(error("BIOS version registry read",status));
	buffer.resize(size/sizeof(wchar_t));
	std::vector<std::string> result;
	std::wstring value;
	for (auto c:buffer) {
		if (c) value+=c;
		else if (!value.empty()) { result.push_back(narrow(value)); value.clear(); }
	}
	if (!value.empty()) return S::error("unterminated BIOS version registry value");
	return S::ok(std::move(result));
}
void devices(Snapshot& s)
{
	HDEVINFO info=SetupDiGetClassDevsW(nullptr,nullptr,nullptr,DIGCF_ALLCLASSES|DIGCF_PRESENT);
	if (info==INVALID_HANDLE_VALUE) { s.devices=decltype(s.devices)::error(error("SetupDiGetClassDevs")); return; }
	std::vector<std::string> ids, links;
	std::string failure, link_failure, bus_failure;
	std::vector<std::uint32_t> buses;
	// pciprop.h's published property key, defined locally to avoid uuid.lib linkage.
	const DEVPROPKEY pci_device_type={{0x3ab22e31,0x8264,0x4b4e,{0x9a,0xf5,0xa8,0xd2,0xd8,0xe3,0x3e,0x62}},1};
	for (DWORD i=0;i<4096;++i) {
		SP_DEVINFO_DATA d{}; d.cbSize=sizeof(d);
		if (!SetupDiEnumDeviceInfo(info,i,&d)) {
			if (GetLastError()!=ERROR_NO_MORE_ITEMS) failure=error("SetupDiEnumDeviceInfo");
			break;
		}
		wchar_t id[4096];
		if (!SetupDiGetDeviceInstanceIdW(info,&d,id,4096,nullptr)) { failure=error("SetupDiGetDeviceInstanceId"); break; }
		ids.push_back(narrow(id));
		if (wcsncmp(id,L"PCI\\",4)==0) {
			DWORD bus=0, kind=0, count=0;
			if (!SetupDiGetDeviceRegistryPropertyW(info,&d,SPDRP_BUSNUMBER,&kind,
				reinterpret_cast<PBYTE>(&bus),sizeof(bus),&count)) bus_failure=error("PCI bus number");
			else if (kind!=REG_DWORD || count!=sizeof(bus)) bus_failure="invalid PCI bus number";
			else buses.push_back(bus);
		}
		DEVPROPTYPE type=0; DWORD device_type=0, returned=0;
		if (SetupDiGetDevicePropertyW(info,&d,&pci_device_type,&type,
			reinterpret_cast<PBYTE>(&device_type),sizeof(device_type),&returned,0)) {
			if (type!=DEVPROP_TYPE_UINT32 || returned!=sizeof(device_type)) link_failure="unexpected PCI device property type";
			else if (device_type==5) links.push_back(narrow(id));
		} else if (GetLastError()!=ERROR_NOT_FOUND && GetLastError()!=ERROR_INVALID_DATA)
			link_failure=error("SetupDiGetDeviceProperty PCI DeviceType");
		if (i==4095) failure="device enumeration exceeds 4096-device limit";
	}
	SetupDiDestroyDeviceInfoList(info);
	s.devices=failure.empty()?decltype(s.devices)::ok(std::move(ids)):decltype(s.devices)::error(failure);
	s.pci_buses=bus_failure.empty()?decltype(s.pci_buses)::ok(std::move(buses)):decltype(s.pci_buses)::error(bus_failure);
	s.pci_links=link_failure.empty()?decltype(s.pci_links)::ok(std::move(links)):decltype(s.pci_links)::error(link_failure);
}
Sample<std::vector<Hid>> hid_strings()
{
	using S=Sample<std::vector<Hid>>;
	GUID guid; HidD_GetHidGuid(&guid);
	HDEVINFO info=SetupDiGetClassDevsW(&guid,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
	if (info==INVALID_HANDLE_VALUE) return S::error(error("HID interface enumeration"));
	std::vector<Hid> result;
	std::string failure;
	for (DWORD i=0;i<128;++i) {
		SP_DEVICE_INTERFACE_DATA d{}; d.cbSize=sizeof(d);
		if (!SetupDiEnumDeviceInterfaces(info,nullptr,&guid,i,&d)) {
			if (GetLastError()!=ERROR_NO_MORE_ITEMS) failure=error("HID interface enumeration");
			break;
		}
		DWORD size=0;
		SetupDiGetDeviceInterfaceDetailW(info,&d,nullptr,0,&size,nullptr);
		if (size<sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || size>65536) { failure="invalid HID path size"; break; }
		Bytes detail(size);
		auto path=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detail.data()); path->cbSize=sizeof(*path);
		if (!SetupDiGetDeviceInterfaceDetailW(info,&d,path,size,nullptr,nullptr)) { failure=error("HID interface path"); break; }
		Hid item; item.path=narrow(path->DevicePath);
		// No input reports are read. Zero-access handles permit keyboard/mouse descriptor queries.
		HANDLE h=CreateFileW(path->DevicePath,0,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
		if (h==INVALID_HANDLE_VALUE) item.indexed_strings[0]=Sample<std::string>::error(error("open HID interface")+"; "+item.path);
		else {
			// These are the indices in the reported QEMU table. Other indices are outside this check.
			for (unsigned index=1;index<=12;++index) {
				wchar_t buffer[128]{};
				if (HidD_GetIndexedString(h,index,buffer,sizeof(buffer))) {
					const auto end=std::find(std::begin(buffer),std::end(buffer),wchar_t(0));
					item.indexed_strings[index]=end==std::end(buffer)?Sample<std::string>::error("unterminated HID string"):
						Sample<std::string>::ok(narrow(std::wstring(buffer,end)));
				} else {
					const DWORD code=GetLastError();
					// USB string indices need not exist. A rejected optional index provides no evidence.
					if (code!=ERROR_INVALID_PARAMETER && code!=ERROR_GEN_FAILURE && code!=ERROR_NOT_SUPPORTED &&
						code!=ERROR_INVALID_FUNCTION && code!=ERROR_NOT_FOUND)
						item.indexed_strings[index]=Sample<std::string>::error(error("HidD_GetIndexedString",code)+"; "+item.path);
				}
			}
			CloseHandle(h);
		}
		result.push_back(std::move(item));
		if (i==127) failure="HID enumeration exceeds 128-interface limit";
	}
	SetupDiDestroyDeviceInfoList(info);
	return failure.empty()?S::ok(std::move(result)):S::error(failure);
}
Sample<Cpu> cpu()
{
	Cpu c; int regs[4];
	__cpuidex(regs,0,0); c.max_basic=std::uint32_t(regs[0]);
	char vendor[13]{};
	memcpy(vendor,regs+1,4); memcpy(vendor+4,regs+3,4); memcpy(vendor+8,regs+2,4); c.vendor=vendor;
	__cpuidex(regs,int(0x80000000u),0); c.max_extended=std::uint32_t(regs[0]);
	for (std::uint32_t id:{1u,6u,7u,0x80000001u,0x80000005u,0x80000006u,0x80000007u,0x80000008u,0x8000000au,0x8000001fu}) {
		if (id<0x80000000u ? id>c.max_basic : id>c.max_extended) continue;
		__cpuidex(regs,int(id),0);
		c.leaves[id]={std::uint32_t(regs[0]),std::uint32_t(regs[1]),std::uint32_t(regs[2]),std::uint32_t(regs[3])};
	}
	if (c.max_extended>=0x80000004) {
		char brand[49]{};
		for (unsigned i=0;i<3;++i) { __cpuidex(regs,int(0x80000002u+i),0); memcpy(brand+16*i,regs,16); }
		c.brand=brand;
	}
	return Sample<Cpu>::ok(std::move(c));
}
Sample<Bytes> nvme(HANDLE disk, STORAGE_PROPERTY_ID property, DWORD type, DWORD request, DWORD length, DWORD subvalue=0)
{
	const auto offset=offsetof(STORAGE_PROPERTY_QUERY,AdditionalParameters);
	Bytes buffer(offset+sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)+length);
	auto q=reinterpret_cast<STORAGE_PROPERTY_QUERY*>(buffer.data());
	q->PropertyId=property; q->QueryType=PropertyStandardQuery;
	auto protocol=reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(buffer.data()+offset);
	protocol->ProtocolType=ProtocolTypeNvme; protocol->DataType=type;
	protocol->ProtocolDataRequestValue=request; protocol->ProtocolDataRequestSubValue=subvalue;
	protocol->ProtocolDataOffset=sizeof(*protocol); protocol->ProtocolDataLength=length;
	DWORD got=0;
	if (!DeviceIoControl(disk,IOCTL_STORAGE_QUERY_PROPERTY,buffer.data(),DWORD(buffer.size()),
		buffer.data(),DWORD(buffer.size()),&got,nullptr)) return Sample<Bytes>::error(error("NVMe IOCTL_STORAGE_QUERY_PROPERTY"));
	if (got>buffer.size()) return Sample<Bytes>::error("NVMe driver returned an invalid byte count");
	buffer.resize(got);
	return nvme_payload(buffer,length,type);
}
Sample<std::vector<Disk>> disks()
{
	using S=Sample<std::vector<Disk>>;
	const GUID disk_guid={0x53f56307,0xb6bf,0x11d0,{0x94,0xf2,0x00,0xa0,0xc9,0x1e,0xfb,0x8b}};
	HDEVINFO info=SetupDiGetClassDevsW(&disk_guid,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
	if (info==INVALID_HANDLE_VALUE) return S::error(error("disk interface enumeration"));
	std::vector<Disk> result;
	std::string failure;
	for (DWORD i=0;i<128;++i) {
		SP_DEVICE_INTERFACE_DATA d{}; d.cbSize=sizeof(d);
		if (!SetupDiEnumDeviceInterfaces(info,nullptr,&disk_guid,i,&d)) {
			if (GetLastError()!=ERROR_NO_MORE_ITEMS) failure=error("SetupDiEnumDeviceInterfaces");
			break;
		}
		DWORD size=0;
		SetupDiGetDeviceInterfaceDetailW(info,&d,nullptr,0,&size,nullptr);
		if (size<sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || size>65536) { failure="invalid disk path size"; break; }
		Bytes detail(size);
		auto path=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detail.data()); path->cbSize=sizeof(*path);
		if (!SetupDiGetDeviceInterfaceDetailW(info,&d,path,size,nullptr,nullptr)) { failure=error("disk path query"); break; }
		Disk item; item.path=narrow(path->DevicePath);
		HANDLE h=CreateFileW(path->DevicePath,0,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
		if (h==INVALID_HANDLE_VALUE) item.identify=Sample<Bytes>::error(error("open disk for property query"));
		else {
			STORAGE_PROPERTY_QUERY q{}; q.PropertyId=StorageDeviceProperty; q.QueryType=PropertyStandardQuery;
			BYTE buffer[4096]{}; DWORD got=0;
			if (!DeviceIoControl(h,IOCTL_STORAGE_QUERY_PROPERTY,&q,sizeof(q),buffer,sizeof(buffer),&got,nullptr))
				item.identify=Sample<Bytes>::error(error("disk bus type query"));
			else if (got<offsetof(STORAGE_DEVICE_DESCRIPTOR,BusType)+sizeof(STORAGE_BUS_TYPE))
				item.identify=Sample<Bytes>::error("truncated storage device descriptor");
			else if (reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer)->BusType==BusTypeNvme) {
				item.identify=nvme(h,StorageAdapterProtocolSpecificProperty,NVMeDataTypeIdentify,1,4096);
				// Namespace 1 is the fresh pass's repro. Do not substitute whole-disk length.
				if (item.identify.state==ReadState::Ok && item.identify.value.size()==4096 &&
					item.identify.value[80]==0 && item.identify.value[81]==4 && item.identify.value[82]==1 && item.identify.value[83]==0 &&
					(item.identify.value[256]&8))
					item.namespace_identify=nvme(h,StorageDeviceProtocolSpecificProperty,NVMeDataTypeIdentify,0,4096,1);
				item.smart=nvme(h,StorageDeviceProtocolSpecificProperty,NVMeDataTypeLogPage,2,512);
				item.firmware=nvme(h,StorageAdapterProtocolSpecificProperty,NVMeDataTypeLogPage,3,512);
				HANDLE read=CreateFileW(path->DevicePath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
				if (read==INVALID_HANDLE_VALUE) item.capacity=decltype(item.capacity)::error(error("open disk for length query"));
				else {
					GET_LENGTH_INFORMATION length{}; DWORD count=0;
					if (!DeviceIoControl(read,IOCTL_DISK_GET_LENGTH_INFO,nullptr,0,&length,sizeof(length),&count,nullptr))
						item.capacity=decltype(item.capacity)::error(error("IOCTL_DISK_GET_LENGTH_INFO"));
					else if (count!=sizeof(length) || length.Length.QuadPart<=0)
						item.capacity=decltype(item.capacity)::error("invalid disk length response");
					else item.capacity=decltype(item.capacity)::ok(std::uint64_t(length.Length.QuadPart));
					CloseHandle(read);
				}
			}
			CloseHandle(h);
		}
		if (item.identify.state!=ReadState::NotApplicable) result.push_back(std::move(item));
		if (i==127) failure="disk enumeration exceeds 128-device limit";
	}
	SetupDiDestroyDeviceInfoList(info);
	return failure.empty()?S::ok(std::move(result)):S::error(failure);
}
Sample<Tpm> tpm()
{
	TBS_CONTEXT_PARAMS2 params{}; params.version=TBS_CONTEXT_VERSION_TWO; params.includeTpm20=1;
	TBS_HCONTEXT context=nullptr;
	TBS_RESULT status=Tbsi_Context_Create(reinterpret_cast<PTBS_CONTEXT_PARAMS>(&params),&context);
	if (status==TBS_E_TPM_NOT_FOUND) return {};
	if (status!=TBS_SUCCESS) return Sample<Tpm>::error(error("Tbsi_Context_Create",status));
	// TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 5).
	const BYTE request[]={0x80,0x01,0,0,0,22,0,0,0x01,0x7a,0,0,0,6,0,0,1,5,0,0,0,5};
	BYTE response[1024]{}; UINT32 size=sizeof(response);
	status=Tbsip_Submit_Command(context,TBS_COMMAND_LOCALITY_ZERO,TBS_COMMAND_PRIORITY_NORMAL,
		request,sizeof(request),response,&size);
	Tbsip_Context_Close(context);
	if (status!=TBS_SUCCESS) return Sample<Tpm>::error(error("TPM2_GetCapability",status));
	auto be32=[&](std::size_t p){return DWORD(response[p])<<24|DWORD(response[p+1])<<16|DWORD(response[p+2])<<8|response[p+3];};
	if (size<19 || size>sizeof(response) || be32(2)!=size || be32(6)!=0 || be32(11)!=6 || be32(15)!=5 || size<59)
		return Sample<Tpm>::error("invalid TPM capability response");
	Tpm identity;
	for (unsigned i=0;i<5;++i) {
		const auto p=19+8*i;
		if (be32(p)!=0x105+i) return Sample<Tpm>::error("unexpected TPM property order");
		std::string value(reinterpret_cast<char*>(response+p+4),4);
		if (i==0) identity.manufacturer=value; else identity.vendor+=value;
	}
	return Sample<Tpm>::ok(std::move(identity));
}
Sample<std::vector<Certificate>> certificates()
{
	using S=Sample<std::vector<Certificate>>;
	NCRYPT_PROV_HANDLE provider=0;
	SECURITY_STATUS status=NCryptOpenStorageProvider(&provider,MS_PLATFORM_CRYPTO_PROVIDER,0);
	if (status!=ERROR_SUCCESS) return S::error(error("NCryptOpenStorageProvider TPM",DWORD(status)));
	std::vector<Certificate> result;
	std::string failure;
	for (const wchar_t* property:{NCRYPT_PCP_RSA_EKCERT_PROPERTY,NCRYPT_PCP_ECC_EKCERT_PROPERTY}) {
		// These properties return HCERTSTORE, not DER bytes. Microsoft PCPTool uses
		// NCryptGetProperty followed by CertEnumCertificatesInStore.
		DWORD size=0; HCERTSTORE store=nullptr;
		status=NCryptGetProperty(provider,property,reinterpret_cast<PBYTE>(&store),sizeof(store),&size,0);
		if (status==NTE_NOT_FOUND || status==NTE_NOT_SUPPORTED) continue;
		if (status!=ERROR_SUCCESS) { failure=error("TPM EK certificate store",DWORD(status)); continue; }
		if (size!=sizeof(store) || !store) { failure="invalid TPM EK certificate-store result"; continue; }
		PCCERT_CONTEXT cert=nullptr;
		unsigned count=0;
		while ((cert=CertEnumCertificatesInStore(store,cert))!=nullptr) {
			char issuer[1024]{}, subject[1024]{};
			DWORD n=CertGetNameStringA(cert,CERT_NAME_SIMPLE_DISPLAY_TYPE,CERT_NAME_ISSUER_FLAG,nullptr,issuer,sizeof(issuer));
			DWORD m=CertGetNameStringA(cert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,subject,sizeof(subject));
			if (n<=1 || n>=sizeof(issuer) || m<=1 || m>=sizeof(subject)) failure="missing or oversized certificate identity";
			else result.push_back({issuer,subject});
			if (++count>=256 || !failure.empty()) {
				if (count>=256) failure="TPM certificate store exceeds 256-certificate limit";
				CertFreeCertificateContext(cert); cert=nullptr; break;
			}
		}
		if (failure.empty() && GetLastError()!=CRYPT_E_NOT_FOUND) failure=error("TPM certificate enumeration");
		CertCloseStore(store,0);
	}
	NCryptFreeObject(provider);
	if (!failure.empty()) return S::error(failure);
	return S::ok(std::move(result));
}
Sample<Bytes> measured_boot()
{
	TBS_CONTEXT_PARAMS2 params{}; params.version=TBS_CONTEXT_VERSION_TWO; params.includeTpm20=1;
	TBS_HCONTEXT context=nullptr;
	TBS_RESULT status=Tbsi_Context_Create(reinterpret_cast<PTBS_CONTEXT_PARAMS>(&params),&context);
	if (status==TBS_E_TPM_NOT_FOUND) return {};
	if (status!=TBS_SUCCESS) return Sample<Bytes>::error(error("measured boot TPM context",status));
	UINT32 size=0;
	status=Tbsi_Get_TCG_Log(context,nullptr,&size);
	if ((status!=TBS_E_INSUFFICIENT_BUFFER && status!=TBS_SUCCESS) || !size || size>limit) {
		Tbsip_Context_Close(context); return Sample<Bytes>::error(error("TCG log size",status));
	}
	Bytes buffer(size);
	status=Tbsi_Get_TCG_Log(context,buffer.data(),&size);
	Tbsip_Context_Close(context);
	if (status!=TBS_SUCCESS || size>buffer.size()) return Sample<Bytes>::error(error("TCG log read",status));
	buffer.resize(size); return Sample<Bytes>::ok(std::move(buffer));
}
struct FirmwarePrivilege {
	HANDLE token=nullptr;
	TOKEN_PRIVILEGES old{};
	bool enabled=false;
	DWORD code=ERROR_SUCCESS;
	FirmwarePrivilege() {
		if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)) { code=GetLastError(); return; }
		TOKEN_PRIVILEGES requested{}; requested.PrivilegeCount=1;
		if (!LookupPrivilegeValueW(nullptr,SE_SYSTEM_ENVIRONMENT_NAME,&requested.Privileges[0].Luid)) { code=GetLastError(); return; }
		requested.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		DWORD length=sizeof(old); SetLastError(ERROR_SUCCESS);
		if (!AdjustTokenPrivileges(token,FALSE,&requested,sizeof(old),&old,&length)) { code=GetLastError(); return; }
		code=GetLastError(); enabled=code==ERROR_SUCCESS;
	}
	~FirmwarePrivilege() {
		if (token) { if (enabled) AdjustTokenPrivileges(token,FALSE,&old,0,nullptr,nullptr); CloseHandle(token); }
	}
};
Sample<Bytes> variable(const wchar_t* name,const wchar_t* guid)
{
	Bytes buffer(65536); DWORD attributes=0;
	DWORD size=GetFirmwareEnvironmentVariableExW(name,guid,buffer.data(),DWORD(buffer.size()),&attributes);
	if (!size) {
		const auto code=GetLastError();
		if (code==ERROR_ENVVAR_NOT_FOUND) return Sample<Bytes>::ok({});
		if (code==ERROR_INVALID_FUNCTION) return {};
		return Sample<Bytes>::error(error("UEFI variable read",code));
	}
	buffer.resize(size); return Sample<Bytes>::ok(std::move(buffer));
}
Uefi uefi()
{
	Uefi result;
	FIRMWARE_TYPE kind=FirmwareTypeUnknown;
	if (!GetFirmwareType(&kind)) { result.boot_order_marker=Sample<Bytes>::error(error("GetFirmwareType")); return result; }
	if (kind!=FirmwareTypeUefi) return result;
	FirmwarePrivilege privilege;
	if (!privilege.enabled) {
		result.boot_order_marker=Sample<Bytes>::error(error("enable SeSystemEnvironmentPrivilege",privilege.code));
		return result;
	}
	const wchar_t* global=L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
	result.boot_order_marker=variable(L"VMMBootOrder0000",L"{668f4529-63d0-4bb5-b65d-6fbb9d36a44a}");
	result.languages=variable(L"PlatformLangCodes",global);
	auto order=variable(L"BootOrder",global);
	if (order.state==ReadState::Error) { result.boot_descriptions=decltype(result.boot_descriptions)::error(order.reason); return result; }
	if (order.state==ReadState::Ok && (order.value.size()>512 || order.value.size()%2)) {
		result.boot_descriptions=decltype(result.boot_descriptions)::error("invalid UEFI BootOrder length"); return result;
	}
	if (order.state==ReadState::Ok && order.value.size()<=512 && order.value.size()%2==0) {
		result.boot_descriptions=decltype(result.boot_descriptions)::ok({});
		for (std::size_t p=0;p<order.value.size();p+=2) {
			wchar_t name[16]; swprintf_s(name,L"Boot%04X",unsigned(order.value[p])|unsigned(order.value[p+1])<<8);
			auto option=variable(name,global);
			if (option.state!=ReadState::Ok || option.value.size()<8) {
				result.boot_descriptions=decltype(result.boot_descriptions)::error("could not read a boot option referenced by BootOrder: "+option.reason); break;
			}
			std::wstring description;
			bool terminated=false;
			for (std::size_t i=6;i+1<option.value.size();i+=2) {
				wchar_t c=option.value[i]|unsigned(option.value[i+1])<<8;
				if (!c) { result.boot_descriptions.value.push_back(narrow(description)); terminated=true; break; }
				description+=c;
			}
			if (!terminated) { result.boot_descriptions=decltype(result.boot_descriptions)::error("unterminated UEFI boot description"); break; }
		}
	}
	return result;
}
// Read event fields rather than rendered messages, which vary with the Windows language.
Sample<std::vector<std::wstring>> event_xml(const wchar_t* channel,const wchar_t* query,DWORD maximum)
{
	using S=Sample<std::vector<std::wstring>>;
	EVT_HANDLE events=EvtQuery(nullptr,channel,query,EvtQueryChannelPath|EvtQueryReverseDirection);
	if (!events) {
		if (GetLastError()==ERROR_EVT_CHANNEL_NOT_FOUND) return {};
		return S::error(error("EvtQuery"));
	}
	std::vector<std::wstring> result;
	std::string failure;
	for (DWORD i=0;i<maximum;++i) {
		EVT_HANDLE event=nullptr; DWORD count=0;
		if (!EvtNext(events,1,&event,1000,0,&count)) {
			if (GetLastError()!=ERROR_NO_MORE_ITEMS) failure=error("EvtNext");
			break;
		}
		DWORD size=0, properties=0;
		EvtRender(nullptr,event,EvtRenderEventXml,0,nullptr,&size,&properties);
		if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size>1024*1024 || size%2) failure="invalid event XML size";
		else {
			std::vector<wchar_t> buffer(size/2);
			if (!EvtRender(nullptr,event,EvtRenderEventXml,size,buffer.data(),&size,&properties)) failure=error("EvtRender");
			else result.emplace_back(buffer.data());
		}
		EvtClose(event);
		if (!failure.empty()) break;
		if (i+1==maximum) failure="event query reached its bounded scan limit; negative result is incomplete";
	}
	EvtClose(events);
	return failure.empty()?S::ok(std::move(result)):S::error(failure);
}
std::wstring field(const std::wstring& xml,const std::wstring& name)
{
	// EvtRender emits XML with single-quoted attributes, no user-controlled markup here.
	for (const auto& tag:{L"<Data Name='"+name+L"'>",L"<Data Name=\""+name+L"\">"}) {
		auto p=xml.find(tag);
		if (p!=std::wstring::npos) {
			p+=tag.size(); auto end=xml.find(L"</Data>",p);
			if (end!=std::wstring::npos) return xml.substr(p,end-p);
		}
	}
	return {};
}
Sample<std::vector<std::string>> storage_history()
{
	auto events=event_xml(L"Microsoft-Windows-Storage-Storport/Operational",
		L"*[System[(EventID=549 or EventID=552 or EventID=504 or EventID=505)]]",4096);
	if (events.state==ReadState::NotApplicable) return {};
	if (events.state!=ReadState::Ok) return Sample<std::vector<std::string>>::error(events.reason);
	std::vector<std::string> found;
	for (const auto& xml:events.value) {
		auto vendor=field(xml,L"VendorId"), product=field(xml,L"ProductId");
		while (!vendor.empty() && vendor.back()==L' ') vendor.pop_back();
		if (vendor==L"QEMU" || product.rfind(L"QEMU ",0)==0) found.push_back(narrow(vendor+L" / "+product));
	}
	return Sample<std::vector<std::string>>::ok(std::move(found));
}
Sample<std::string> processor_power()
{
	// Restrict to this boot. The duration predicate uses event timestamps, not locale text.
	std::wstring query=L"*[System[Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=55 and TimeCreated[timediff(@SystemTime) <= "+
		std::to_wstring(GetTickCount64())+L"]]]";
	auto events=event_xml(L"System",query.c_str(),257);
	if (events.state!=ReadState::Ok) return Sample<std::string>::error(events.reason);
	if (events.value.empty()) return {};
	const auto value=field(events.value.front(),L"PerformanceImplementation");
	if (value.empty()) return Sample<std::string>::error("processor event lacks PerformanceImplementation");
	return Sample<std::string>::ok(narrow(value));
}
Sample<std::vector<std::string>> gateways()
{
	using S=Sample<std::vector<std::string>>;
	PMIB_IPFORWARD_TABLE2 routes=nullptr; PMIB_IPNET_TABLE2 neighbours=nullptr;
	ULONG code=GetIpForwardTable2(AF_INET,&routes);
	if (code!=NO_ERROR) return S::error(error("GetIpForwardTable2",code));
	code=GetIpNetTable2(AF_INET,&neighbours);
	if (code!=NO_ERROR) { FreeMibTable(routes); return S::error(error("GetIpNetTable2",code)); }
	std::vector<std::string> found;
	for (ULONG i=0;i<routes->NumEntries;++i) {
		const auto& route=routes->Table[i];
		if (route.DestinationPrefix.PrefixLength!=0) continue;
		for (ULONG j=0;j<neighbours->NumEntries;++j) {
			const auto& neighbour=neighbours->Table[j];
			if (neighbour.InterfaceIndex!=route.InterfaceIndex || neighbour.Address.Ipv4.sin_addr.s_addr!=route.NextHop.Ipv4.sin_addr.s_addr ||
				neighbour.PhysicalAddressLength!=6 || neighbour.State==NlnsUnreachable || neighbour.State==NlnsIncomplete) continue;
			char address[INET_ADDRSTRLEN]{}, mac[32]{};
			InetNtopA(AF_INET,const_cast<IN_ADDR*>(&route.NextHop.Ipv4.sin_addr),address,sizeof(address));
			sprintf_s(mac,"%02x:%02x:%02x:%02x:%02x:%02x",neighbour.PhysicalAddress[0],neighbour.PhysicalAddress[1],
				neighbour.PhysicalAddress[2],neighbour.PhysicalAddress[3],neighbour.PhysicalAddress[4],neighbour.PhysicalAddress[5]);
			found.push_back(std::string(address)+" "+mac);
		}
	}
	FreeMibTable(routes); FreeMibTable(neighbours);
	if (found.empty()) return {}; // No cached neighbour is not evidence of a clean gateway.
	return S::ok(std::move(found));
}
}

void qemu_adversary_checks()
{
	adversary::Snapshot snapshot;
	devices(snapshot);
	snapshot.cpu=cpu();
	snapshot.hid=hid_strings();
	snapshot.smbios=firmware('RSMB',0);
	snapshot.bios_versions=bios_versions();
	snapshot.acpi=acpi_tables();
	snapshot.disks=disks();
	snapshot.tpm=tpm();
	if (snapshot.tpm.state!=ReadState::NotApplicable) {
		snapshot.certificates=certificates();
		snapshot.measured_boot=measured_boot();
	}
	snapshot.uefi=uefi();
	snapshot.storage_history=storage_history();
	snapshot.processor_power=processor_power();
	snapshot.gateways=gateways();
	for (const auto& result:adversary::evaluate(snapshot)) {
		auto title=wide(result.id+" "+result.title);
		_print_check_text(title.c_str());
		_print_check_result(result.outcome,title.c_str());
		if (!result.evidence.empty()) {
			auto evidence=wide(result.evidence);
			for (auto& c:evidence) if (c<L' ' || c==127) c=L' ';
			if (evidence.size()>2048) evidence=evidence.substr(0,2048)+L" [truncated]";
			wprintf(L"    %s\n",evidence.c_str());
			LOG_PRINT(_T("%s"),evidence.c_str());
		}
	}
}
