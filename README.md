# Pestilence

![N|Solid](https://cdn.thecollector.com/wp-content/uploads/2021/11/sabatelli-decameron-plague-florence-print.jpg)
<span style="color:gray"><small> The black death in florence 1348, caused by the Yersinia <b>Pestis</b> bacterium.</small></span>


Pestilence is a project under the 42 malware branch. The objective is to make an oligomorphic virus that infect ELF binaries located in two temporary folders.

## Viruses:
> A program that can infect other programs by modifying them to include a possibly evolved copy of itself - <ins>Fred Cohen</ins>

Basically they inject their own source code to a binary, change it to execute their code first before jumping to the original binary main.<br/>
![N|Solid](https://i.postimg.cc/V6pSGhzB/sc.png)
In this way each time the infected binary runs, the virus code execute and It spreads again.



## Oligomorphic Virus:
To make life hard for antivirus companies and reverse engineers, virus devs started freestyling to hide the functionality of the virus. One of the early approaches involved encrypting the main body, and injecting a small piece of code that executed first to decrypt the original virus and then jumping to it.</br>

Oligomorphic viruses, also known as semi-polymorphic viruses, carry with them a set of decryptors. Each time the virus replicat, It choose a random decryptor, making the code not static and always changing.
</br>
![N|Solid](https://www.researchgate.net/profile/Babak-Bashari-Rad/publication/235641122/figure/fig3/AS:299935946821642@1448521710512/Structure-and-mechanism-of-oligomorphic-virus.png)


##  The project:
Our goal is to create an oligomorphic code, when It execute, It does the following:
- Check if the program is being debugged and exit if positive.
- Check if an active process is being run and exit if positive.
- Decrypt the **Virus code** and execute it.
- Encrypt the virus code with a new key and select a random decryptor.
- Patch the virus to jump to the original binary's main entry point.
- Patch the host to execute our virus.

## Anti Debug: 

If we run ptrace on a process and It fails, It indicates that the program is being controlled by another process (mostly a debugger).

To check if an active process (strace in this case) is running, the approach involves looping through all the process file entries in **/proc** and checking the **com** file, which contains the process name. If found, the virus exits.
 

## Decryption:
Viruses used to load the decryption code into a buffer, decrypt the content, and jump to the start of the buffer to execute it. Others would decrypt the code directly where Its stored.</br>
This methods no longer work nowaday, as modern systems implemented protections like the stack can be non-exeutable and the text section is non-writable (cant modify code directly).</br>
One method I figured was the creation of an executable memory region using mmap. This region is allocated with the size of the stub.</br>
The encryption is a simple cyclic **XOR** over a key, each byte of the virus is XORed with the the corresponding character of the key, based on Its position: key[i % 8], (since key is 8 bytes long).

## Infection:

The project specifies that the infection should target binaries located in the directories **/tmp/test** and **/tmp/test**.
The programs has to be ELF x86_64.
For each directory, we open the folder, and get all the  directory entries.
Regular file entries are processed by verifying that they are valid binaries and not already infected.
The injection method we used is PT_NOTE to PT_LOAD, [Check Resources](#Resources).</br>
Pestilence only carries 7 decryptors, one of which is chosen randomly during the injection process.
Each replication generates a new key, this key will be used to encrypt the virus body,aka **routine**.
The injection is divided into 3 parts:
-  First part: Write the anti-debug mechanism and the chosen decryptor.</br>
-  Second part: Encrypt routine, and write it.
-  Third part: Copy what is left from pestilence (key, signature ...).


## Patching:
Since the patching occurs in the **routine** code, addresses of the values to be patched are passed as arguments and stored in the stack.</br>
Here are the changes that need to be made :</br>
- Update e_entry in the ELF header to point to the virtual address where the virus will be loaded in memory.
- Modify the key used in Pestilence.
- Set the offset to the original e_entry (the address to jump to after the virus finishes execution).


## Files:
- pestilence.asm: check for antidebug, decrypt and load virus to memory.
- routine.asm: contains the core functionality of the replication of the virus.
- set.py: sript that compile and encrypt routine.asm with the default key and inject Its bytecode in pestilence.asm. The script has a value (size of the routine) that should be changed with the old size (current value in decryptors).

## Note:
this was the first time I make something in assembly, I did not respect any coding style or conventions. So I treated registers as my legos. The code might seems messy but that would be good as anti-reverse technique :D
## Resources
- Oligomorphic viruses :
https://www.informit.com/articles/article.aspx?p=366890&seqNum=4</br>Talks about polymorphism but mentions oligomorphism :
https://samples.vx-underground.org/Papers/Other/Code%20Mutation/0000-00-00%20-%20Introductory%20Primer%20To%20Polymorphism%20in%20Theory%20and%20Practice.pdf
- PT_NOTE to PT_LOAD:
https://tmpout.sh/1/2.html
https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/

