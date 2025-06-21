# PROXANDO



# ABOUT


This software is a replica of one of the most iconic and used tools of offensive security: proxychains<br>
In all these years of work, without proxychains I would not have been able to conduct several activities, but there were episodes instead in which I would have found useful features that the original author has not yet introduced
<br>
<br>
The code is certainly a mess BUT it does its job! <br>
On this occasion I also wanted to thank the entire community of pentesters and hackers! Thanks to your studies, researches, articles, posts, blogs, videos you made me grow. This software is a tribute to all of you, I hope you find it useful!:D<br>

# ENCHANTMENTS

- UDP support by --udp flag ( both ipv4 - ipv6 )<br>
- SOCKS proxy selection by -id flag<br>
<br>
Feel free to share what others features may be useful!<br>




# EXAMPLES & USAGE

Before you ask me, proxychains's references are intentional(:<br>







# PREREQUISITES

- GLIBC_2.38<br>



# INSTALLATION

git clone https://github.com/NULLhere/Proxando.git<br>
cd Proxando<br>
make clean && CFLAGS="-DDEBUG" ./configure && make ----> to enable logs <br>
make clean && ./configure && make		               ----> to disable logs<br>


# LIMITATIONS

The limitations are the same of the original one: this program works only on dynamically linked programs, so what cannot be intercepted is:
- binaries statically compiled
- direct syscalls ( mount, ntpdate, etc etc.. )

I'm not planning to add support for that anytime soon, but I want to!<br>
I'm just busy with something else now, but I think the more convenient way to intercept direct syscall is using ptrace() and that would require a lllllot of work, so stay tuned<br>



# ABOUT ISSUES

If you find issues please report them in the more detailed way you can, so I can reproduce them in my environment! Softwares involved, wireshark traffic, what proxy you are using, the scenario, etc etc.. <br>
As I said, I don't know when ( and if ) I will be able to fix them! So feel free to make a pull request containing the fix, I will check it when I can(:<br>
