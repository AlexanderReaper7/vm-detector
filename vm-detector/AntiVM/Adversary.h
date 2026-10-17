#pragma once

#include "../Shared/CheckOutcome.h"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace adversary {
using Bytes = std::vector<std::uint8_t>;

enum class ReadState { Ok, Error, NotApplicable };

template<class T> struct Sample {
	ReadState state = ReadState::NotApplicable;
	T value{};
	std::string reason;
	static Sample ok(T value) { return {ReadState::Ok, std::move(value), {}}; }
	static Sample error(std::string reason) { return {ReadState::Error, {}, std::move(reason)}; }
};

struct Cpu {
	std::string vendor, brand;
	std::uint32_t max_basic = 0, max_extended = 0;
	std::map<std::uint32_t, std::array<std::uint32_t, 4>> leaves;
};

struct Disk {
	std::string path;
	Sample<Bytes> identify, smart, firmware, namespace_identify;
	Sample<std::uint64_t> capacity;
};

struct Hid {
	std::string path;
	std::map<unsigned, Sample<std::string>> indexed_strings;
};

struct Tpm { std::string manufacturer, vendor; };
struct Certificate { std::string issuer, subject; };
struct Uefi {
	Sample<Bytes> boot_order_marker, languages;
	Sample<std::vector<std::string>> boot_descriptions;
};

struct Snapshot {
	Sample<std::vector<std::string>> devices;
	Sample<Bytes> smbios;
	Sample<std::vector<Hid>> hid;
	Sample<std::vector<std::string>> bios_versions;
	Sample<std::vector<Bytes>> acpi;
	Sample<Cpu> cpu;
	Sample<std::vector<Disk>> disks;
	Sample<Tpm> tpm;
	Sample<std::vector<Certificate>> certificates;
	Uefi uefi;
	Sample<std::vector<std::string>> storage_history;
	Sample<std::vector<std::string>> gateways, pci_links;
	Sample<std::vector<std::uint32_t>> pci_buses;
	Sample<Bytes> measured_boot;
	Sample<std::string> processor_power;
};

struct Result {
	std::string id, title;
	CheckOutcome outcome;
	std::string evidence;
};

// These parsers are shared by the Windows collector and the native fixture tests.
bool valid_acpi(const Bytes& data, std::string& error);
Sample<Bytes> nvme_payload(const Bytes& response, std::size_t requested,
	std::uint32_t expected_type);
std::vector<Result> evaluate(const Snapshot& snapshot);
}
