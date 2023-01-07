Build an ELF file from an esp8266 ROM and flash dump
----------------------------------------------------

According to various documents (e.g. https://github.com/esp8266/esp8266-wiki/wiki/Memory-Map),
the memory range 40000000h-40010000h contains the built in ESP library code.
Functions in this memory area are listed in the ROM linker file in the Non-OS SDK:
https://github.com/espressif/ESP8266_NONOS_SDK/blob/master/ld/eagle.rom.addr.v6.ld

We can download that code from an actual SoC using esptool.py:

`esptool.py dump_mem 0x40000000 0x10000 rom.bin`

The SPI Flash stores the actual user program, that can be downloaded with the following command:

`esptool.py read_flash 0 4194304 flash.bin`

The esp8266's built in bootloader loads a second stage boot loader from the beginning of the flash.
My understanding is that the built in bootloader can only load an image, while
the second stage boot loader has tha capability to also update the flash image.
The user program's segments start at 1000h in the flash.

Based on rom.bin, flash.bin and eagle.rom.addr.v6.ld, makeelf.py generates an elf file
that contains the ROM code and the user application from flash. This elf file then can
be loaded to disassebly tools, like rizin.



    rizin.exe rom.elf

    [0x401000c0]> bf sym.strlen
    [0x401000c0]> pD @ sym.strlen
                ; XREFS(77)
    ┌ sym.strlen ();
    │           0x4000bf4c      addi  a3, a2, -4
    │           0x4000bf4f      movi  a4, 255
    │           0x4000bf52      l32r  a5, data.400003f4                    ; [0x400003f4:4]=0xff00
    │           0x4000bf55      l32r  a6, data.400003f8                    ; [0x400003f8:4]=0xff0000
    │           0x4000bf58      l32r  a7, data.400003fc                    ; [0x400003fc:4]=0xff000000
    │       ┌─< 0x4000bf5b      bbsi  a2, 0, 0x4000bf64
    │      ┌──< 0x4000bf5e      bbsi  a2, 1, 0x4000bf6e
    │     ┌───< 0x4000bf61      j     0x4000bf80
    │     ││└─> 0x4000bf64      l8ui  a8, a3, 4
    │     ││    0x4000bf67      addi.n a3, a3, 1
    │     ││┌─< 0x4000bf69      beqz.n a8, 0x4000bf90
    │    ┌────< 0x4000bf6b      bbci  a3, 1, 0x4000bf80
    │    ││└──> 0x4000bf6e      addi.n a3, a3, 2
    │    ││ │   0x4000bf70      l32i.n a8, a3, 0
    │    ││┌──< 0x4000bf72      bnone a8, a6, 0x4000bfa0
    │   ┌─────< 0x4000bf75      bany  a8, a7, 0x4000bf80
    │   │││││   0x4000bf78      addi.n a3, a3, 3
    │   │││││   0x4000bf7a      sub   a2, a3, a2
    │   │││││   0x4000bf7d      ret.n
        │││││   0x4000bf7f  ~   excw
    │   │││││   ; CODE XREF from sym.strlen @ 0x4000bf61
    │  ┌└└└───> 0x4000bf80      l32i.n a8, a3, 4
    │  ╎   ││   0x4000bf82      addi.n a3, a3, 4
    │  ╎  ┌───< 0x4000bf84      bnone a8, a4, 0x4000bf92
    │  ╎ ┌────< 0x4000bf87      bnone a8, a5, 0x4000bf98
    │  ╎┌─────< 0x4000bf8a      bnone a8, a6, 0x4000bfa0
    │  └──────< 0x4000bf8d      bany  a8, a7, 0x4000bf80
    │   ││││└─> 0x4000bf90      addi.n a3, a3, 3
    │   ││└───> 0x4000bf92      sub   a2, a3, a2
    │   ││ │    0x4000bf95      ret.n
        ││ │    0x4000bf97  ~   clamps a1, a11, 7
    │   │└────> 0x4000bf98      addi.n a3, a3, 1
    │   │  │    0x4000bf9a      sub   a2, a3, a2
    │   │  │    0x4000bf9d      ret.n
        │  │    0x4000bf9f  ~   clamps a2, a11, 7
    │   └──└──> 0x4000bfa0      addi.n a3, a3, 2
    │           0x4000bfa2      sub   a2, a3, a2
    └           0x4000bfa5      ret.n