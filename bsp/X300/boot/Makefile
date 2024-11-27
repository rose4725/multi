# Copyright(C) 2020 Hex Five Security, Inc. - All Rights Reserved

.PHONY: all
all:
# Compile boot.S
	$(CC) -march=$(RISCV_ARCH) -mabi=$(RISCV_ABI) -ffreestanding -Wall -x assembler-with-cpp -c -o boot.o boot.S
# Compile verify_sign.c with OpenSSL
	$(CC) -march=$(RISCV_ARCH) -mabi=$(RISCV_ABI) -ffreestanding -Wall -I"C:/vcpkg/installed/x64-windows/include" -c -o verify_sign.o verify_sign.c
# Link all object files
	$(CC) -march=$(RISCV_ARCH) -mabi=$(RISCV_ABI) -ffreestanding -Wall -T ../memory.lds -T linker.lds -nostdlib -Xlinker --gc-sections -Wl,-Map,boot.map -o boot.elf ./boot.o ./verify_sign.o -L"C:/vcpkg/installed/x64-windows/lib" -lssl -lcrypto
# Generate hex and list files
	$(OBJCOPY) -O ihex -j.boot boot.elf boot.hex
	$(OBJDUMP) --source --all-headers --demangle --disassemble --line-numbers --reloc --wide boot.elf > boot.lst

.PHONY: clean
clean:
#	Remove: add verify_sign
	rm -f boot.o boot.hex boot.elf boot.lst boot.map verify_sign.o
