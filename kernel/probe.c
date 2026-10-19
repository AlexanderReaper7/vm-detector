/* Fixed read-only probes. No caller-controlled MSR, port, address or payload. */
#include <ntddk.h>
#include <wdmsec.h>
#include <intrin.h>
#include "../vm-detector/Kernel/Protocol.h"

C_ASSERT(sizeof(VmdKernelReply) == VMD_KERNEL_REPLY_SIZE);
static const ULONG msrs[VMD_MSR_COUNT] = {
    0x4b564d00, 0x4b564d01, 0x4b564d02, 0x4b564d03,
    0x4b564d04, 0x4b564d05, 0xdeadbeef, 0xffffffff
};
static const GUID device_class = {
    0xf7621686, 0x48b8, 0x41cc, {0xb0, 0x0a, 0xc7, 0x8a, 0xc4, 0x57, 0x36, 0x26}
};
static UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\VmDetectorKernel");
static UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"\\DosDevices\\VmDetectorKernel");
extern USHORT vmd_read_cs(void);
/* Assembly leaves keep faulting instructions inside calls covered by SEH. */
extern unsigned __int64 vmd_read_msr(ULONG index);
extern UCHAR vmd_read_port(USHORT port);
extern void vmd_write_selector(USHORT selector);

static void firmware_read(USHORT selector, UCHAR *bytes, ULONG size)
{
    vmd_write_selector(selector);
    for (ULONG i = 0; i < size; i++) bytes[i] = vmd_read_port(0x511);
}

static void probe(VmdKernelReply *reply)
{
    int registers[4];
    RtlZeroMemory(reply, sizeof(*reply));
    reply->version = VMD_KERNEL_VERSION;
    reply->size = sizeof(*reply);
    reply->cs = vmd_read_cs();
    reply->irql = KeGetCurrentIrql();
    __cpuid(registers, 1);
    reply->cpuid_ecx = (ULONG)registers[2];
    for (ULONG i = 0; i < VMD_MSR_COUNT; i++) {
        reply->msrs[i].index = msrs[i];
        __try {
            unsigned __int64 value = vmd_read_msr(msrs[i]);
            reply->msrs[i].low = (ULONG)value;
            reply->msrs[i].high = (ULONG)(value >> 32);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            reply->msrs[i].status = GetExceptionCode();
        }
    }
    __try {
        UCHAR bytes[4];
        firmware_read(0, reply->signature, 4);
        for (ULONG i = 0; i < 8; i++) reply->dma_signature[i] = vmd_read_port((USHORT)(0x514 + i));
        firmware_read(1, bytes, 4);
        reply->firmware_features = (ULONG)bytes[0] | (ULONG)bytes[1] << 8 |
            (ULONG)bytes[2] << 16 | (ULONG)bytes[3] << 24;
        /* Unsupported/undiscovered interface is not a successful negative scan. */
        if (!(reply->firmware_features & 1) || (reply->firmware_features & ~3u)) {
            BOOLEAN known = RtlCompareMemory(reply->signature, "AMIF", 4) == 4 ||
                RtlCompareMemory(reply->signature, "QEMU", 4) == 4;
            reply->firmware_status = known ? STATUS_DATA_ERROR : VMD_NOT_SUPPORTED;
            return;
        }
        firmware_read(0x19, bytes, 4);
        reply->firmware_count = (ULONG)bytes[0] << 24 | (ULONG)bytes[1] << 16 |
            (ULONG)bytes[2] << 8 | (ULONG)bytes[3];
        if (reply->firmware_count > VMD_FWCFG_FILES) {
            reply->firmware_status = STATUS_BUFFER_OVERFLOW;
            return;
        }
        for (ULONG i = 0; i < reply->firmware_count * 64; i++) reply->directory[i] = vmd_read_port(0x511);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        reply->firmware_status = GetExceptionCode();
    }
}

static NTSTATUS complete(PIRP irp, NTSTATUS status, ULONG_PTR bytes)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack->MajorFunction == IRP_MJ_CLOSE || stack->MajorFunction == IRP_MJ_CLEANUP)
        return complete(irp, STATUS_SUCCESS, 0);
    if (stack->MajorFunction == IRP_MJ_CREATE)
        return complete(irp, stack->FileObject->FileName.Length ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_SUCCESS, 0);
    if (stack->MajorFunction != IRP_MJ_DEVICE_CONTROL ||
        stack->Parameters.DeviceIoControl.IoControlCode != VMD_IOCTL_PROBE)
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    if (stack->Parameters.DeviceIoControl.InputBufferLength != 0)
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VmdKernelReply))
        return complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return complete(irp, STATUS_INVALID_DEVICE_STATE, 0);
    /* Serialize selector/data reads so concurrent clients cannot mix directories. */
    ExAcquireFastMutex((PFAST_MUTEX)device->DeviceExtension);
    probe((VmdKernelReply *)irp->AssociatedIrp.SystemBuffer);
    ExReleaseFastMutex((PFAST_MUTEX)device->DeviceExtension);
    return complete(irp, STATUS_SUCCESS, sizeof(VmdKernelReply));
}

static void unload(PDRIVER_OBJECT driver)
{
    IoDeleteSymbolicLink(&device_link);
    IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    PDEVICE_OBJECT device;
    UNICODE_STRING security = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    UNREFERENCED_PARAMETER(registry);
    NTSTATUS status = IoCreateDeviceSecure(driver, sizeof(FAST_MUTEX), &device_name,
        0x8337, FILE_DEVICE_SECURE_OPEN, FALSE, &security, &device_class, &device);
    if (!NT_SUCCESS(status)) return status;
    ExInitializeFastMutex((PFAST_MUTEX)device->DeviceExtension);
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) driver->MajorFunction[i] = dispatch;
    driver->DriverUnload = unload;
    status = IoCreateSymbolicLink(&device_link, &device_name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
