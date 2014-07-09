public SpoilContext
	
.data

.code

; all assembly routines go here

SpoilContext proc
	mov rax,0deadbee1h
	mov rcx, 0deadbee2h
	mov rdx, 0deadbee3h
	;mov rbx, 0deadbeefh
	mov r8, 0deadbee4h
	mov r9, 0deadbee5h
	;mov r10, 0deadbeefh
		;mov	rax,0xdeadbeefdeadbeefh
		;mov			rbx,	0xbeefdeadh 0xdeadbeefdeadbeefh
		;mov			rcx,	0xdadadadah
		;mov			rdx,	0xbabababah
		;mov			r8,		0xfafafafah
		;mov			r9,		0xeaeaeaeah

    ret
    
SpoilContext endp

END ; end of assembly file


	