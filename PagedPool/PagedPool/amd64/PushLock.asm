public PushLock
.data

.code
PushLock proc
	add     word ptr [r12+1C6h],1
    ret
    
PushLock endp

END ; end of assembly file


	