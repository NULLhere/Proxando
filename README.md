# PROXANDO



# ABOUT


This software is a replica of one of the most iconic and used tools of offensive security: proxychains<br>
Essentially, this is a TCP + UDP proxychains implementation <br>
Over the years, I would not have been able to carry out several activities without proxychains. However, there were times when I would have found certain features useful — features that the original author has not yet introduced
<br>
<br>
The code is certainly a mess BUT it gets the job done! <br>
I also want to take this opportunity to thank the entire community of pentesters, red teamers, and hackers. Your studies, research, articles, posts, blogs, and videos have helped me grow. This software is a tribute to all of you in the cybersecurity world, I hope you find it useful!:D<br>

# ENCHANTMENTS

- UDP support by --udp flag ( both ipv4 - ipv6 )<br>
- SOCKS proxy selection by -id flag<br>
<br>
Feel free to share what others features may be useful!<br>




# EXAMPLES & USAGE

Before you ask me, proxychains's references are intentional(:<br>



Compiling and POC:

https://github.com/user-attachments/assets/883313d9-afee-48d2-ab85-b4f0826abb9f




The configuration file is always proxychains.conf, but you can choose what socks proxy you want to use to forward your traffic, just adding an ID as prefix. For example:


https://github.com/user-attachments/assets/cd996e70-2dc9-445c-a480-fe99df9f86c4







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

I'm not planning to add support for those anytime soon, but I would love to in the future!<br>
I'm just busy with other things at the moment. I believe the most viable way to intercept direct syscalls would be through ptrace(), but that would require a looooot of work - so stay tuned!<br>



# ABOUT ISSUES

If you find any issues, please report them in as much detail as possible so I can try to reproduce them in my environment! Include things like: the software involved, Wireshark traffic captures, the proxy you are using, the scenario, and anything else that might help <br>
As I mentioned earlier, I don't know when (or if) I will be able to fix them, so feel free to open a pull request with a fix, I will review it as soon as I can!(:<br>
