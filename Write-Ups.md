 ## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [New Orleans](#new-orleans)
- [Sydney](#sydney)
- [Hanoi](#hanoi)
- [Cusco](#cusco)
- [Reykjavik](#reykjavik)
- [Whitehorse](#whitehorse)
- [Montevideo](#montevideo)
- [Johannesburg](#johannesburg)
- [Santa Cruz](#santa-cruz)
- [Addis Ababa](#addis-ababa)

## Introduction

Welcome to my exploit write up on the embedded security challenges from the website [Microcorruption](https://microcorruption.com/). 

## New Orleans


Just looking through the disassembly you can see a fishy function right off the bat. We can see a function called create_password, which if we look at it we see it adding hex codes to memory address r15. If we convert those hexcodes to ascii we can see that it makes, NMTIhRY. If we enter that in as the password, we unlock the door, meaning we solved this challenge.

```asm
447e <create_password>
447e:  3f40 0024      mov	#0x2400, r15
4482:  ff40 4e00 0000 mov.b	#0x4e, 0x0(r15)
4488:  ff40 4d00 0100 mov.b	#0x4d, 0x1(r15)
448e:  ff40 5400 0200 mov.b	#0x54, 0x2(r15)
4494:  ff40 4900 0300 mov.b	#0x49, 0x3(r15)
449a:  ff40 6800 0400 mov.b	#0x68, 0x4(r15)
44a0:  ff40 5200 0500 mov.b	#0x52, 0x5(r15)
44a6:  ff40 5900 0600 mov.b	#0x59, 0x6(r15)
44ac:  cf43 0700      mov.b	#0x0, 0x7(r15)
44b0:  3041           ret
```

### Solved

Password = NMTIhRY

## Sydney


Looking at the disassembly this time there isn't any fishy functions like create_password. If we look at the check_password function this time we see that it is comparing hexcodes to the memory address location r15. If look at 
location 444a in the main function. We can see that the after getting the password the program puts the stack pointer into the r15 memory address. Which means the program is comparing the hexcodes to the password. If we enter in the hexcodes, 2d28462c5827735f, as the password the door fails to unlock. This doesn't mean our assumptions wrong, because if we swap the hexcode pairs 282d2c4627585f73, the door unlocks. The reason that worked is because of endianness swaps them during execution.

```asm
4438 <main>
4438:  3150 9cff      add	#0xff9c, sp
443c:  3f40 b444      mov	#0x44b4 "Enter the password to continue.", r15
4440:  b012 6645      call	#0x4566 <puts>
4444:  0f41           mov	sp, r15
4446:  b012 8044      call	#0x4480 <get_password>
444a:  0f41           mov	sp, r15
444c:  b012 8a44      call	#0x448a <check_password>
4450:  0f93           tst	r15
4452:  0520           jnz	#0x445e <main+0x26>
4454:  3f40 d444      mov	#0x44d4 "Invalid password; try again.", r15
4458:  b012 6645      call	#0x4566 <puts>
445c:  093c           jmp	#0x4470 <main+0x38>
445e:  3f40 f144      mov	#0x44f1 "Access Granted!", r15
4462:  b012 6645      call	#0x4566 <puts>
4466:  3012 7f00      push	#0x7f
446a:  b012 0245      call	#0x4502 <INT>
446e:  2153           incd	sp
4470:  0f43           clr	r15
4472:  3150 6400      add	#0x64, sp

448a <check_password>
448a:  bf90 282d 0000 cmp	#0x2d28, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 2c46 0200 cmp	#0x462c, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 2758 0400 cmp	#0x5827, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 5f73 0600 cmp	#0x735f, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```

### Solved

Password = 282d2c4627585f73

## Hanoi


If we run the program we get the message that passwords can only be as big as 16 characters. We can test that restraint by entering a ton of As as the password. If we look at the login function and put a breakpoint at location 455a. We can see that the program is looking for hexcode cb at the memory location 2410. If we look at that memory location we can see that we are overwrote that location with As. So, let's see if adding hexcode cb to that location will unlock the door. If we pad the password with 16 hexcode 41s, then add the hexcode cb at the end. We can see that this password unlocks the door solving the challenge.

```asm
4520 <login>
4520:  c243 1024      mov.b	#0x0, &0x2410
4524:  3f40 7e44      mov	#0x447e "Enter the password to continue.", r15
4528:  b012 de45      call	#0x45de <puts>
452c:  3f40 9e44      mov	#0x449e "Remember: passwords are between 8 and 16 characters.", r15
4530:  b012 de45      call	#0x45de <puts>
4534:  3e40 1c00      mov	#0x1c, r14
4538:  3f40 0024      mov	#0x2400, r15
453c:  b012 ce45      call	#0x45ce <getsn>
4540:  3f40 0024      mov	#0x2400, r15
4544:  b012 5444      call	#0x4454 <test_password_valid>
4548:  0f93           tst	r15
454a:  0324           jz	$+0x8
454c:  f240 3000 1024 mov.b	#0x30, &0x2410
4552:  3f40 d344      mov	#0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call	#0x45de <puts>
455a:  f290 cb00 1024 cmp.b	#0xcb, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
4566:  b012 de45      call	#0x45de <puts>
456a:  b012 4844      call	#0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov	#0x4501 "That password is not correct.", r15
4574:  b012 de45      call	#0x45de <puts>
4578:  3041           ret



2400:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
2410:   4141 4141 4141 4141 4141 4141 0000 0000   AAAAAAAAAAAA....
2420:   0000 0000 0000 0000 0000 0000 0000 0000   ................
```

### Solved

Password = 41414141414141414141414141414141cb

## Cusco


When we put in a password longer than 16 characters we get this message, "insn address unaligned", in the debugger console. Normally the message is "CPUOFF flag set; program no longer running. CPU must now be reset". This means we are possible overwritting the instruction pointer. If we use the password, ABCDEFGHIJKLMNOPQRSTUVWXYZ, and put a breakpoint on the return call in the login function. If we step once we see that in the instruction pointer is 5251 or RQ. That means we are overwriting the pointer. If we add the location of the unlock_door function, 4446, in place RQ in our password, we can get the program to go there and unlock the door for us. Converting the everything to hex and swapping the unlock_door function's location for endianness solves this challenge.

### Solved

Password = 414243444546474849505152535455564644
