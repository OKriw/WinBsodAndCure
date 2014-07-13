public KeBugPatch
.data

; all data variables in your asm code goes here
opcodes0   dq   0   ; 64 bit data
opcodes1   dq	0	;
tmp		   dq	0	;
.code
KeBugPatch proc
    	mov    rax, opcodes0
		bswap  rax
		mov    rcx, tmp
		mov    dword ptr [rcx], rax
		mov    rax, opcodes1
		bswap  rax
		mov    dword ptr [rcx+4], rax
	
    ret
    
KeBugPatch endp

END 