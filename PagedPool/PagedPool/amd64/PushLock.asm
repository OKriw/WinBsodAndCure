public PushLock
.data

.code

; all assembly routines go here

PushLock proc
	add     word ptr [r12+1C6h],1
	;mov r10, 0deadbeefh
		;mov	rax,0xdeadbeefdeadbeefh
		;mov			rbx,	0xbeefdeadh 0xdeadbeefdeadbeefh
		;mov			rcx,	0xdadadadah
		;mov			rdx,	0xbabababah
		;mov			r8,		0xfafafafah
		;mov			r9,		0xeaeaeaeah

    ret
    
PushLock endp

END ; end of assembly file


	