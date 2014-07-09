public KeBugPatch
public MyPatch
.data
.code
KeBugPatch proc
		mov		rax, cr0
		and		rax, 0fffffffffffeffffh
		mov		cr0, rax
		;bswap rdx
		mov	word ptr [rcx], 0bb48h
		mov qword ptr [rcx+2], rdx
		mov word ptr [rcx+10], 0d3ffh
		mov rax, cr0
		or rax, 10000h
		mov cr0, rax
    ret
    
KeBugPatch endp

MyPatch proc
	mov rdx, 0fffff8000167e492h
	call rdx
MyPatch endp
END 
