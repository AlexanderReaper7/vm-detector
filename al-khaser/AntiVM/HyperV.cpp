#include "pch.h"
#include "HyperV.h"


BOOL check_hyperv_driver_objects()
{
	auto driverList = enumerate_object_directory(L"\\Driver");
	if (driverList == nullptr)
	{
		return FALSE;
	}
	for (wchar_t* driver : *driverList)
	{
		if (StrCmpCW(driver, L"VMBusHID") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(driver, L"vmbus") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(driver, L"vmgid") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(driver, L"IndirectKmd") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(driver, L"HyperVideo") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(driver, L"hyperkbd") == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}


BOOL check_hyperv_global_objects()
{
	auto globalObjs = enumerate_object_directory(L"\\GLOBAL??");
	if (globalObjs == nullptr)
	{
		return FALSE;
	}
	for (wchar_t* globalObj : *globalObjs)
	{
		// VMBus, the VM Generation Counter and the VM GID object are created by
		// the Hyper-V stack / a hypervisor-provided vmgenid device, so they are
		// genuine virtualization tells.
		if (StrStrW(globalObj, L"VMBUS#") != NULL)
		{
			return TRUE;
		}
		if (StrCmpCW(globalObj, L"VmGenerationCounter") == 0)
		{
			return TRUE;
		}
		if (StrCmpCW(globalObj, L"VmGid") == 0)
		{
			return TRUE;
		}
		// VDRVROOT is deliberately NOT matched. It is the control device of
		// vdrvroot.sys, the "Virtual Drive Root Enumerator", a Microsoft inbox,
		// Microsoft-signed driver for VHD/virtual-disk support that ships in the
		// stock Windows image and is present (and loaded) on bare-metal Windows
		// too. It is not Hyper-V-specific, so matching it reported a VM on
		// physical machines. See al-khaser issue on the Hyper-V false positives.
	}
	return FALSE;
}
