# Asm patterns incompatible with the SFrame format
This file contains examples of assembly patterns that are incompatible with the
SFrame format along with my guess as to what each individual pattern is actually
doing.

This isn't meant to cover everything but mostly act as a note of recurring
patterns where DWARF debug info cannot be converted to SFrame.

## 1. Stack Probes
A stack probe ends up involving ASM that looks like this
```
    lea    r11,[rsp-0x4000]
start:
    sub    rsp,0x1000
    or     QWORD PTR [rsp],0x0
    cmp    rsp,r11
    jne    start
```

This results in a DWARF unwind table record that looks like this
```
  - offset: 0x000058fc (end = 0x0000590d)
    cfa:    r11+16392
    reg:    RA = *(CFA-8)
```

Since the CFA is relative to `r11` there is no way to represent this as a
SFrame FDE. However, the unique thing about this one case is that the emitted
code could be changed to work with SFrames fairly easily by using `rbp` to
store the CFA address instead of `r11`:
```
    push    rbp
    lea     rbp,[rsp-0x4000]
start:
    sub     rsp,0x1000
    or      qword ptr [rsp], 0x0
    cmp     rsp, rbp
    jne     start
    add     rsp, 0x8
    mov     rbp, [rsp-0x4000]
```
