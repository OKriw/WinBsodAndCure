;#include "Poolalloc.h"

EXTERN Param1:QWORD
EXTERN Param2:QWORD	
EXTERN Param3:QWORD	
EXTERN Param4:QWORD
EXTERN Param5:QWORD	
public GetArgs

.code
GetArgs proc
		mov			Param1,	rcx
		mov			Param2, rdx
		mov			Param3, r8
		mov			Param4,	r9
		mov			Param5,	r10
		
    ret	
    
GetArgs endp

END ; end of assembly file

