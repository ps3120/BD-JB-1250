#include <unistd.h>
#include <string.h>
#include <ps4/kernel.h>

typedef unsigned char u8;

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

void send_notification(const char* message) {
    notify_request_t req;
    bzero(&req, sizeof req);
    strncpy(req.message, message, sizeof req.message);
    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

void patch_aio(void * kbase) {
    // Search pattern: 74 49 E9 DF 00 00 00
    char search_pattern[] = "7449e9df000000";
    
    unsigned long found = kernel_find_pattern((unsigned long)kbase, 0xC00000, search_pattern);
    
    if (!found) {
        send_notification("AIO already patched");
        return;
    }
    
    // Calculate base offset from the found pattern
    size_t base_offset = found - (unsigned long)kbase;
    
    // Apply patches using relative offsets from the found pattern
    {
        unsigned long addr = (unsigned long)kbase + base_offset;
        u8 patch[] = {0xeb, 0x48};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x42;
        u8 nop_patch[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        kernel_copyin(nop_patch, addr, sizeof(nop_patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x4a;
        u8 patch[] = {0x41, 0x83, 0xbf, 0xa0, 0x04, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x58;
        u8 patch[] = {0x49, 0x8b, 0x87, 0xd0, 0x04, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x65;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0xb0, 0x04, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x7d;
        u8 patch[] = {0x49, 0x8b, 0x87, 0x40, 0x05, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0x8a;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0x20, 0x05, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xa2;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xc0, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xae;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xe0, 0x00, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xc1;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x00, 0x01, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xcd;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x20, 0x01, 0x00, 0x00};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    {
        unsigned long addr = (unsigned long)kbase + base_offset + 0xde;
        u8 patch[] = {0x49, 0x8b, 0xff};
        kernel_copyin(patch, addr, sizeof(patch));
    }
    
    send_notification("AIO patch completed successfully");
}

int main() {
    send_notification("Starting AIO patch...");
    patch_aio((void*)KERNEL_ADDRESS_IMAGE_BASE);
    return 0;
}
