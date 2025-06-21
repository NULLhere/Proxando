# Proxando



ABOUT


This software is a replica of one of the most iconic and used tools of offensive security: proxychains
In all these years of work, without proxychains I would not have been able to conduct several activities, but there were episodes instead in which I would have found useful features that the original author has not yet introduced
The code is certainly a mess BUT it does its job! 
On this occasion I also wanted to thank the entire community of pentesters and hackers! Thanks to your studies, researches, articles, posts, blogs, videos you made me grow. This software is a tribute to all of you, I hope you find it useful!:D

ENCHANTMENTS

- UDP support by --udp flag ( both ipv4 - ipv6 )
- socks proxy selection by -id flag

Feel free to share what others features may be useful!




EXAMPLES & USAGE

Before you ask me, proxychains's references are intentional(:







PREREQUISITES

- GLIBC_2.38



INSTALLATION

git clone https://github.com/NULLhere/Proxando/
cd Proxando
make clean && CFLAGS="-DDEBUG" ./configure && make ----> to enable logging & debug
make clean && ./configure && make		               ----> to disable logging & debug


LIMITATIONS

The limitations are the same of the original one: this program works only on dynamically linked programs, so what cannot be intercepted is:
- binaries statically compiled
- direct syscalls ( mount, ntpdate, etc etc.. )

I'm not planning to add support for that anytime soon, but I want to!
I'm just busy with something else now, but I think the more convenient way to intercept direct syscall is using ptrace() and that would require a lllllot of work, so stay tuned



ABOUT ISSUES

If you find issues please report them in the more detailed way you can, so I can reproduce them in my environment! Softwares involved, wireshark traffic, what proxy you are using, the scenario, etc etc.. 
As I said, I don't know when ( and if ) I will be able to fix them! So feel free to make a pull request containing the fix, I will check it when I can(:




License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
