ifdef PS4_PAYLOAD_SDK
    include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
else
    $(error PS4_PAYLOAD_SDK is undefined)
endif

PAYLOAD := aiofix_USBpayload.elf
SRCS    := main.c

CFLAGS := -Wall -Werror -g -fPIC -ffunction-sections -Wl,--gc-sections

all: $(PAYLOAD)

%.elf: $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm -f *.o *.elf
