#pragma once

#include <stdint.h>

#define VMD_KERNEL_VERSION 1u
#define VMD_MSR_COUNT 8u
#define VMD_FWCFG_FILES 64u
/* Vendor device type, METHOD_BUFFERED, FILE_READ_ACCESS, function 0x800. */
#define VMD_IOCTL_PROBE 0x83376000u
#define VMD_DEVICE_PATH L"\\\\.\\VmDetectorKernel"
#define VMD_PRIVILEGED_INSTRUCTION 0xc0000096u
#define VMD_NOT_SUPPORTED 0xc00000bbu

typedef struct VmdMsr {
    uint32_t index, status, low, high;
} VmdMsr;

/* Fixed-width, pointer-free response, identical in C, x86 and x64 consumers. */
typedef struct VmdKernelReply {
    uint32_t version, size, cs, irql, cpuid_ecx;
    uint32_t firmware_status, firmware_features, firmware_count;
    uint8_t signature[4], dma_signature[8];
    VmdMsr msrs[VMD_MSR_COUNT];
    uint8_t directory[VMD_FWCFG_FILES * 64];
} VmdKernelReply;

#define VMD_KERNEL_REPLY_SIZE (44u + 16u * VMD_MSR_COUNT + 64u * VMD_FWCFG_FILES)
