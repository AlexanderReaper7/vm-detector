/* Fixed 82574L query, invoked only by the separate NETKERNEL option. */
C_ASSERT(sizeof(VmdNetworkReply) == VMD_NETWORK_REPLY_SIZE);
static void network_probe(VmdNetworkReply *r)
{
    PCI_SLOT_NUMBER slot;
    ULONG found = 0, observed = 0;
    RtlZeroMemory(r, sizeof(*r));
    r->version = VMD_NETWORK_VERSION; r->size = sizeof(*r);
    r->cs = vmd_read_cs(); r->irql = KeGetCurrentIrql();
    r->status = STATUS_UNSUCCESSFUL;
    /* Bound enumeration to conventional segment-zero PCI configuration. */
    for (ULONG bus = 0; bus < 256; bus++) {
        for (ULONG dev = 0; dev < 32; dev++) {
            BOOLEAN multi = FALSE;
            for (ULONG fn = 0; fn < 8; fn++) {
                UCHAR config[64];
                slot.u.AsULONG = 0;
                slot.u.bits.DeviceNumber = dev; slot.u.bits.FunctionNumber = fn;
                RtlZeroMemory(config, sizeof(config));
                ULONG n = HalGetBusDataByOffset(PCIConfiguration, bus, slot.u.AsULONG,
                    config, 0, sizeof(config));
                if (n < 4 || *(USHORT *)config == 0xffff || *(USHORT *)config == 0) {
                    if (!fn) break;
                    continue;
                }
                observed++;
                if (!fn) multi = (n >= 15 && (config[14] & 0x80));
                if (*(USHORT *)config == 0x8086 && *(USHORT *)(config + 2) == 0x10d3) {
                    r->bus = bus; r->slot = slot.u.AsULONG; found++;
                }
                if (!multi) break;
            }
        }
    }
    if (!observed) return; /* An unavailable PCI query is not an absent NIC. */
    if (!found) { r->status = VMD_NOT_SUPPORTED; return; }
    if (found != 1) { r->status = STATUS_BUFFER_OVERFLOW; return; }
    r->status = STATUS_DEVICE_DATA_ERROR;
    if (HalGetBusDataByOffset(PCIConfiguration, r->bus, r->slot, r->pci[0], 0, 256) != 256) return;
    ULONG bar = *(ULONG *)(r->pci[0] + 0x10);
    if ((bar & 15) || !(bar & 0xfffffff0) || !(*(USHORT *)(r->pci[0] + 4) & 2)) return;
    /* Only the identified device's already assigned 32-bit BAR, never caller input.
     * No BAR sizing, PCI writes, link changes, resets, DMA or NVM writes. */
    PHYSICAL_ADDRESS pa; pa.QuadPart = bar & 0xfffffff0;
    volatile ULONG *mmio = MmMapIoSpace(pa, 0x1000, MmNonCached);
    if (!mmio) { r->status = STATUS_INSUFFICIENT_RESOURCES; return; }
    ULONG original = READ_REGISTER_ULONG(mmio + 0x14 / 4);
    __try {
        for (ULONG pass = 0; pass < 2; pass++) {
            if (HalGetBusDataByOffset(PCIConfiguration, r->bus, r->slot, r->pci[pass], 0, 256) != 256) __leave;
            r->eecd[pass] = READ_REGISTER_ULONG(mmio + 0x10 / 4);
            for (ULONG word = 0; word < 64; word++) {
                ULONG value = 0;
                WRITE_REGISTER_ULONG(mmio + 0x14 / 4, (word << 2) | 1);
                for (ULONG poll = 0; poll < 1000; poll++) {
                    value = READ_REGISTER_ULONG(mmio + 0x14 / 4);
                    if (value & 2) break;
                    KeStallExecutionProcessor(1);
                }
                if (!(value & 2) || ((value >> 2) & 0x3fff) != word) {
                    r->status = STATUS_IO_TIMEOUT;
                    __leave;
                }
                r->eeprom[pass][word] = (USHORT)(value >> 16);
            }
        }
        r->status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r->status = GetExceptionCode();
    }
    /* EERD is a command register, not a restorable saved data value. Re-read
     * its original address rather than writing its status/data fields back. */
    WRITE_REGISTER_ULONG(mmio + 0x14 / 4, (original & 0xfffc) | 1);
    MmUnmapIoSpace((PVOID)mmio, 0x1000);
}
