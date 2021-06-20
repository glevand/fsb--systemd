/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "disk.h"
#include "graphics.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "secure-boot.h"
#include "splash.h"
#include "util.h"

static void __attribute__((used)) _debug(const char *func, int line,
        const CHAR16 *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        Print(L"*** debug: %a:%d: ", func, line);
        VPrint(fmt, ap);
        va_end(ap);
}

#if defined(DEBUG)
# define debug(_args...) do {_debug(__func__, __LINE__, _args);} while(0)
#else
# define debug(_args...) while(0) {_debug("ERROR: ", __LINE__, _args);}
#endif

static const UINT64 fsb_watchdogcode = 0x10022;

static const UINT32 __attribute__((used)) attributes_nv_ba_ra = (
        EFI_VARIABLE_NON_VOLATILE
        | EFI_VARIABLE_BOOTSERVICE_ACCESS
        | EFI_VARIABLE_RUNTIME_ACCESS
);

static const UINT32 __attribute__((used)) attributes_ba_ra = (
        EFI_VARIABLE_BOOTSERVICE_ACCESS
        | EFI_VARIABLE_RUNTIME_ACCESS
);

static void __attribute__((used)) efi_wdt_set(UINTN timeout)
{
//   IN UINTN                    Timeout,
//   IN UINT64                   WatchdogCode,
//   IN UINTN                    DataSize,
//   IN CHAR16                   *WatchdogData OPTIONAL

        EFI_STATUS result;

        result = uefi_call_wrapper(BS->SetWatchdogTimer, 4, timeout,
                fsb_watchdogcode, 0, NULL);

        if (EFI_ERROR(result)) {
                debug(L"SetWatchdogTimer FAILED: %d\n", result);
        } else {
                debug(L"SetWatchdogTimer OK (%llu sec.).\n", timeout);
        }

}

struct vendor_id {
        const CHAR16 str[37];
        const EFI_GUID bin;
};

static const struct vendor_id efi_vendor_id = {
        .str = L"8be4df61-93ca-11d2-aa0d-00e098032b8c",
        .bin = {0x8be4df61, 0x93ca, 0x11d2,
                {0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}},
};

static const struct vendor_id fsb_vendor_id = {
        .str = L"9c4b2ad9-cff6-485b-ac30-5398aec7605c",
        .bin = {0x9c4b2ad9, 0xcff6, 0x485b,
                {0xac, 0x30, 0x53, 0x98, 0xae, 0xc7, 0x60, 0x5c}},
};

struct efi_var_name {
        const struct vendor_id *vid;
        const CHAR16 *name;
};

static void __attribute__((used)) efi_var_print(const struct efi_var_name *vn)
{
        _cleanup_freepool_ CHAR8 *buf = NULL;
        UINTN size;
        EFI_STATUS result;

        result = efivar_get_raw(&vn->vid->bin, vn->name, &buf, &size);

        if (EFI_ERROR(result)) {
                debug(L"efivar_get_raw '%s' FAILED.\n", vn->name);
        } else {
                UINTN i;

                debug(L"efivar_get_raw '%s' OK: size = %d\n", vn->name, size);
                debug(L"'%s' = ", vn->name);
                for (i = 0; i < size; i++) {
                        Print(L"%02x ", buf[i]);
                }
                Print(L"\n");
        }
}

struct efi_16_var {
        struct efi_var_name vn;
        UINT32 attributes;
        UINT16 value;
};

static EFI_STATUS get_16(struct efi_16_var *v)
{
        EFI_STATUS result;

        result = efivar_get_uint16_le(&v->vn.vid->bin, v->vn.name, &v->value);

        if (EFI_ERROR(result)) {
                debug(L"%s: get %s FAILED: %d\n", v->vn.vid->str, v->vn.name,
                        result);
        } else {
                debug(L"%s: get %s OK: 0x%x (%d)\n", v->vn.vid->str, v->vn.name,
                        v->value, v->value);
        }

        return result;
}

static EFI_STATUS set_16(struct efi_16_var *v)
{
        EFI_STATUS result;

        result = efivar_set_uint16_le(&v->vn.vid->bin, v->vn.name, v->value,
                v->attributes);

        if (EFI_ERROR(result)) {
                debug(L"%s: set %s FAILED: %d\n", v->vn.vid->str, v->vn.name,
                      result);
        } else {
                debug(L"%s: set %s OK: 0x%x (%d)\n", v->vn.vid->str, v->vn.name,
                        v->value, v->value);
        }

        return result;
}

static void test_efi_16_var(void)
{
        struct efi_16_var v = {
                .vn.vid = &efi_vendor_id,
                .attributes = attributes_nv_ba_ra,
        };
        EFI_STATUS result;
        UINT16 old_value;

        v.vn.name = L"BootCurrent";
        result = get_16(&v);

        v.vn.name = L"BootNext";
        result = get_16(&v);

        old_value = v.value;
        v.value = 0xab;
        result = set_16(&v);

        result = get_16(&v);

        v.value = old_value;
        result = set_16(&v);

        (void)result;
}

static UINT16 map_bump_index(UINT16 index)
{
        return index ? 0 : 1;
}

static UINT16 map_get_value(const struct efi_16_var *map,
        const struct efi_16_var *index)
{
        return (map->value >> (8 * index->value)) & 0xff;
}

static void run_fail_safe_boot(void)
{
        static const UINT16 fsb_counter_max = 3;
        struct efi_16_var fsb_counter = {
                .vn.name = L"fsb-counter",
                .vn.vid = &fsb_vendor_id,
                .attributes = attributes_nv_ba_ra,
        };
        struct efi_16_var fsb_map = {
                .vn.name = L"fsb-map",
                .vn.vid = &fsb_vendor_id,
                .attributes = attributes_nv_ba_ra,
        };
        struct efi_16_var fsb_index = {
                .vn.name = L"fsb-index",
                .vn.vid = &fsb_vendor_id,
                .attributes = attributes_nv_ba_ra,
        };
        struct efi_16_var efi_boot_next = {
                .vn.name = L"BootNext",
                .vn.vid = &efi_vendor_id,
                .attributes = attributes_nv_ba_ra,
        };
        EFI_STATUS result;

        result = get_16(&fsb_counter);

        if (EFI_ERROR(result)) {
                debug(L"get_16 fsb_counter FAILED: %d\n", result);
        }

        result = get_16(&fsb_map);

        if (EFI_ERROR(result)) {
                debug(L"get_16 fsb_map FAILED: %d\n", result);
        }

        result = get_16(&fsb_index);

        if (EFI_ERROR(result)) {
                debug(L"get_16 fsb_index FAILED: %d\n", result);
        }

        if (fsb_counter.value >= fsb_counter_max) {
                UINT16 old_index;
                UINT16 old_map;

                old_index = fsb_index.value;
                old_map = map_get_value(&fsb_map, &fsb_index);

                fsb_index.value = map_bump_index(fsb_index.value);

                result = set_16(&fsb_index);

                if (EFI_ERROR(result)) {
                        debug(L"set_16 fsb_index FAILED: %d\n", result);
                }

                Print(L"FSB: Switching boot: %d (%d) -> %d (%d)\n", old_index,
                        old_map, fsb_index.value,
                        map_get_value(&fsb_map, &fsb_index));

                fsb_counter.value = 0;
        }

        fsb_counter.value++;

        result = set_16(&fsb_counter);

        if (EFI_ERROR(result)) {
                debug(L"set_16 fsb_counter FAILED: %d\n", result);
        }

        efi_boot_next.value = map_get_value(&fsb_map, &fsb_index);

        result = set_16(&efi_boot_next);

        if (EFI_ERROR(result)) {
                debug(L"set_16 efi_boot_next FAILED: %d\n", result);
        }

        Print(L"fail-safe: Vendor ID = '%s'\n", fsb_vendor_id.str);
        Print(L"fail-safe: counter = %d\n", fsb_counter.value);
        Print(L"fail-safe: index = %d\n", fsb_index.value);
        Print(L"fail-safe: next = %d\n", efi_boot_next.value);
}

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-stub " GIT_VERSION " ####";

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        EFI_LOADED_IMAGE *loaded_image;
        CHAR8 *sections[] = {
                (CHAR8 *)".cmdline",
                (CHAR8 *)".linux",
                (CHAR8 *)".initrd",
                (CHAR8 *)".splash",
                NULL
        };
        UINTN addrs[ELEMENTSOF(sections)-1] = {};
        UINTN offs[ELEMENTSOF(sections)-1] = {};
        UINTN szs[ELEMENTSOF(sections)-1] = {};
        CHAR8 *cmdline = NULL;
        UINTN cmdline_len;
        CHAR16 uuid[37];
        EFI_STATUS err;

        InitializeLib(image, sys_table);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
                Print(L"Error getting a LoadedImageProtocol handle: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        err = pe_memory_locate_sections(loaded_image->ImageBase, sections, addrs, offs, szs);
        if (EFI_ERROR(err)) {
                Print(L"Unable to locate embedded .linux section: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        if (szs[0] > 0)
                cmdline = (CHAR8 *)(loaded_image->ImageBase) + addrs[0];

        cmdline_len = szs[0];

        /* if we are not in secure boot mode, or none was provided, accept a custom command line and replace the built-in one */
        if ((!secure_boot_enabled() || cmdline_len == 0) && loaded_image->LoadOptionsSize > 0 &&
            *(CHAR16 *) loaded_image->LoadOptions > 0x1F) {
                CHAR16 *options;
                CHAR8 *line;

                options = (CHAR16 *)loaded_image->LoadOptions;
                cmdline_len = (loaded_image->LoadOptionsSize / sizeof(CHAR16)) * sizeof(CHAR8);
                line = AllocatePool(cmdline_len);
                for (UINTN i = 0; i < cmdline_len; i++)
                        line[i] = options[i];
                cmdline = line;

#if ENABLE_TPM
                /* Try to log any options to the TPM, especially manually edited options */
                err = tpm_log_event(SD_TPM_PCR,
                                    (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->LoadOptions,
                                    loaded_image->LoadOptionsSize, loaded_image->LoadOptions);
                if (EFI_ERROR(err)) {
                        Print(L"Unable to add image options measurement: %r", err);
                        uefi_call_wrapper(BS->Stall, 1, 200 * 1000);
                }
#endif
        }

        /* Export the device path this image is started from, if it's not set yet */
        if (efivar_get_raw(LOADER_GUID, L"LoaderDevicePartUUID", NULL, NULL) != EFI_SUCCESS)
                if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                        efivar_set(LOADER_GUID, L"LoaderDevicePartUUID", uuid, 0);

        /* If LoaderImageIdentifier is not set, assume the image with this stub was loaded directly from the
         * UEFI firmware without any boot loader, and hence set the LoaderImageIdentifier ourselves. Note
         * that some boot chain loaders neither set LoaderImageIdentifier nor make FilePath available to us,
         * in which case there's simple nothing to set for us. (The UEFI spec doesn't really say who's wrong
         * here, i.e. whether FilePath may be NULL or not, hence handle this gracefully and check if FilePath
         * is non-NULL explicitly.) */
        if (efivar_get_raw(LOADER_GUID, L"LoaderImageIdentifier", NULL, NULL) != EFI_SUCCESS &&
            loaded_image->FilePath) {
                _cleanup_freepool_ CHAR16 *s;

                s = DevicePathToStr(loaded_image->FilePath);
                efivar_set(LOADER_GUID, L"LoaderImageIdentifier", s, 0);
        }

        /* if LoaderFirmwareInfo is not set, let's set it */
        if (efivar_get_raw(LOADER_GUID, L"LoaderFirmwareInfo", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s;

                s = PoolPrint(L"%s %d.%02d", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                efivar_set(LOADER_GUID, L"LoaderFirmwareInfo", s, 0);
        }

        /* ditto for LoaderFirmwareType */
        if (efivar_get_raw(LOADER_GUID, L"LoaderFirmwareType", NULL, NULL) != EFI_SUCCESS) {
                _cleanup_freepool_ CHAR16 *s;

                s = PoolPrint(L"UEFI %d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
                efivar_set(LOADER_GUID, L"LoaderFirmwareType", s, 0);
        }

        /* add StubInfo */
        if (efivar_get_raw(LOADER_GUID, L"StubInfo", NULL, NULL) != EFI_SUCCESS)
                efivar_set(LOADER_GUID, L"StubInfo", L"systemd-stub " GIT_VERSION, 0);

        if (szs[3] > 0)
                graphics_splash((UINT8 *)((UINTN)loaded_image->ImageBase + addrs[3]), szs[3], NULL);

        if (0) {
                test_efi_16_var();
        }

        run_fail_safe_boot();

        if (1) {
                efi_wdt_set(5);
        }

        debug(L"Calling linux_exec\n");

        err = linux_exec(image, cmdline, cmdline_len,
                         (UINTN)loaded_image->ImageBase + addrs[1],
                         (UINTN)loaded_image->ImageBase + addrs[2], szs[2]);

        graphics_mode(FALSE);
        Print(L"Execution of embedded linux image failed: %r\n", err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
}
