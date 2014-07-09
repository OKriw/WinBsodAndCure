#include "ntddk.h"
#include "PoolAlloc.h"
	
//

//////////////
NTSTATUS DriverEntry( __in PDRIVER_OBJECT pDriverObject, __in PUNICODE_STRING path){
	NTSTATUS Status;
	UNICODE_STRING DeviceName;
	UNICODE_STRING DosDeviceName;
	PDEVICE_OBJECT	Dev=NULL ;
	HANDLE CrashThread;
	
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE]= 
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]= 
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;
	
	RtlInitUnicodeString(&DeviceName,DEVICE_NAME);
	Status=IoCreateDevice(
			pDriverObject,
			0,
			&DeviceName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&fakeDevice);
	if (!NT_SUCCESS (Status))
		return Status;

	RtlInitUnicodeString (&DosDeviceName, DOS_DEVICE_NAME);
	Status = IoCreateSymbolicLink (&DosDeviceName, &DeviceName);
	if (!NT_SUCCESS (Status))
	{
		IoDeleteDevice (fakeDevice);
		return Status;
	}
	//__debugbreak();
	KdPrint (("driver entry is finished\n"));
	/*BugCheckDataPool = (PKBUGCHECK_CALLBACK_RECORD)ExAllocatePool(NonPagedPool, 1024);
	KeInitializeCallbackRecord(BugCheckDataPool);
	KeRegisterBugCheckCallback(BugCheckDataPool, PoolPtrBugCheckCallback, 0, 0, "BUGCHECKPOOL");*/
	KBSOD();
	/*Status=PsCreateSystemThread(&CrashThread, 	// ThreadHandle
		GENERIC_ALL,								// DesiredAccess
		NULL,									// ObjectAttributes
		NULL,									//
		NULL,
		EventFunc,
		NULL);
		
	if(NT_SUCCESS(Status)){
		DbgPrint("Thread created succesfully\n");
	}else{
		DbgPrint("Failed to create thread\n");
	}*/
	Switcher=0;

	return STATUS_SUCCESS;

};//http://jpassing.com/2008/03/12/walking-the-stack-of-the-current-thread/

/*VOID PoolPtrBugCheckCallback(__in  PVOID Buffer,__in  ULONG Length)
{ 
	__debugbreak();
	RtlCaptureContext(&Context);
	HalDisplayString("\n\nHello World!\n\n");
	KdPrint(("This is my callback connected with PoolPtr!\n"));
	return;
};*/




NTSTATUS DriverControl(IN PDEVICE_OBJECT  pDeviceObject, __in PIRP irp){
	//PVOID Mm=0;
	NTSTATUS Status;
	ULONG ControlCode;
	PVOID pBuffer = NULL;
	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(irp);
	ULONG InputLength  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	
	pBuffer = irp->UserBuffer;
	
	switch (IrpStack->MajorFunction) {  
		case IRP_MJ_CREATE: 
				Status = STATUS_SUCCESS; 
			break;  
		case IRP_MJ_CLOSE: 
				Status = STATUS_SUCCESS;
			break;  
		case IRP_MJ_DEVICE_CONTROL:
			ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
			switch(ControlCode){	
				
				case IOCTL_TO_ALLOCATE_PAGED_POOL:
					KdPrint (("IOCTL_TO_ALLOCATE_PAGED_POOL \n"));
					//__debugbreak();
					PoolAlloc();
					break;		
				case IOCTL_IF_POOL_WAS_PAGED:
					KdPrint (("IOCTL_IF_POOL_WAS_PAGED \n"));
					//__debugbreak();	
					TestForSwap(PoolPtr);	
					break;	
				case IOCTL_RAISE_IRQL:
					__debugbreak();
					KdPrint(("Raising irql\n"));
					RaiseIrql();
					break;
				case IOCTL_GET_PAGE:
					__debugbreak();
					KdPrint (("IOCTL_GAT_PAGE \n"));
					break;
					

			} 
			irp->IoStatus.Status      = STATUS_SUCCESS;
			break;
	}
        
        irp->IoStatus.Information = InputLength;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
		KdPrint(("Finishing proccessing!\n"));
        return STATUS_SUCCESS;
}
VOID RaiseIrql(){
	KIRQL OldIrql;
	NTSTATUS Status;
	char* TryToAcessPool;
	CONTEXT       TestContext;
	//MyStackTrace64();
	Switcher=1;
	
	//RtlCaptureContext(&TestContext);
	OldIrql=KeGetCurrentIrql();
	KeRaiseIrql(DISPATCH_LEVEL,
				&OldIrql);
	//RtlCaptureContext(&TestContext);
	
	TryToAcessPool=*(char*)PoolPtr;
	KdPrint(("We are going to fix Everything!\n"));
	//Status = GetPage(PVOID PoolPtr);
	 KeLowerIrql(
				OldIrql);
	Switcher=0;

}
VOID PoolAlloc(){
		NTSTATUS Status;
		PHYSICAL_ADDRESS LowAddress;
		PHYSICAL_ADDRESS HighAddress;
		PHYSICAL_ADDRESS SkipBytes;
		SIZE_T TotalBytes = 4096;
		LowAddress.QuadPart = 0,
		HighAddress.QuadPart = (ULONGLONG)-1;
		SkipBytes.QuadPart = 0;
						
		PoolPtr= MmAllocatePagesForMdlEx(
			LowAddress,
			HighAddress,
			SkipBytes,
			TotalBytes,
			1,
			MM_ALLOCATE_PREFER_CONTIGUOUS
);
		
		AddressPoolptr= MmMapLockedPagesSpecifyCache(
							PoolPtr,
							KernelMode,
							1,
							NULL,
							FALSE,
							NormalPagePriority);
		if(AddressPoolptr){
				DbgPrint("Fail to map meory");}
			
		Status= MmProtectMdlSystemAddress(
							PoolPtr,
							PAGE_READONLY);


}
/*VOID PoolAlloc(){
	NTSTATUS Status;
	 PtrAddress=NULL;
	 CurrprocHandle=PsGetCurrentProcessId();
	 PtrAddressSize=512;
	Status=ZwAllocateVirtualMemory(
				CurrprocHandle,
				&PtrAddress,
				0,
				&PtrAddressSize,
				MEM_COMMIT,
				PAGE_EXECUTE_READ );
	if(!Status){
		DbgPrint("Status is not Success");
	}/*
	/*SIZE_T SizePagedBuffer=512;
	char* JunkInfo="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
	//__debugbreak();
	KdPrint(("Pool allocation \n"));
	PoolPtr=ExAllocatePoolWithTag(
								PagedPool,
								SizePagedBuffer,
								'TagP');
								
	 RtlCopyMemory(
						PoolPtr,
						JunkInfo,
						sizeof(JunkInfo)
);
	//return PoolPtr; 
};*/

BOOLEAN TestForSwap(PVOID PoolPtr){
	NTSTATUS Status;
	SIZE_T TotalBytes = 4096;
	char* SomeTrash = "This is statment to poot in memory!";
	__debugbreak();
	RtlCopyMemory(
					AddressPoolptr,
					SomeTrash,
					TotalBytes 
					);
	/*HANDLE hEvent;
	UNICODE_STRING us;
	PVOID pEvent;
	LARGE_INTEGER timeout;
	
  //------------------------------------------------
	timeout.QuadPart = -5 * 10000000;
	//__debugbreak();
	Status = ZwCreateEvent(	&hEvent,
							EVENT_ALL_ACCESS,
							NULL,
							NotificationEvent,
							FALSE);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("Failed to create event \n");
		return Status;
	}

	Status = ObReferenceObjectByHandle(
		hEvent, 		//Handle
		EVENT_ALL_ACCESS,	//DesiredAccess
		NULL,			//ObjectType
		KernelMode,		//AccessMode
		&pEvent,		//Object
		NULL);			//HandleInformation

	if (!NT_SUCCESS(Status)) {
		ZwClose(hEvent);
		DbgPrint("Failed to reference event \n");
		return Status;
	}

	while(MmIsAddressValid(PoolPtr)){
		KdPrint(("Still Valid\n"));
		KeWaitForSingleObject(
			pEvent,  		//Object
			Executive,		//WaitReason
			KernelMode,		//WaitMode
			FALSE,			//Alertable
			&timeout);			//Timeout
}

	__debugbreak();
	DbgPrint("Finished Waiting\n");
	ObDereferenceObject(pEvent);
	ZwClose(hEvent);
	return Status;*/
	
};

NTSTATUS GetPage(PVOID PoolPtr){
	KdPrint(("We are gonna fix it, baby!\n"));
}

VOID DriverUnload(__in PDRIVER_OBJECT pDriverObject){
	UNICODE_STRING DosDeviceName;
	KeDeregisterBugCheckCallback(BugCheckDataPool);
	KdPrint (("fakedevice: Unload\n"));
	RtlInitUnicodeString( &DosDeviceName, DOS_DEVICE_NAME );
	__debugbreak();
	IoDeleteSymbolicLink( &DosDeviceName );
	if (fakeDevice)
		IoDeleteDevice( fakeDevice );

}

VOID KBSOD(){
	KIRQL OldIrql;
	KIRQL OldIrqlDpc;
	PVOID	check;
	size_t SizePagedBuffer=256;
	UNICODE_STRING KeBugCheckExAdress;
	UNICODE_STRING KeBugCheck2Adress;
	UINT64 opcodes0;
	UINT64 opcodes1;
	
    RtlInitUnicodeString(
            &KeBugCheckExAdress,
            L"KeBugCheckEx");
	//__debugbreak();
    AdressKeBugCheckEx=MmGetSystemRoutineAddress(& KeBugCheckExAdress);
	DbgPrint("KeBugCheckExAdress = %p\n",AdressKeBugCheckEx);
	
	opcodes0=(UINT64)AdressKeBugCheckEx;
	opcodes1=(UINT64)&MyBugCheckFunc; 
	//48Ba  92E4 6701 00F8 FFFF  FFd2
	
	__debugbreak();	
	OldIrql=KeGetCurrentIrql();
	KeRaiseIrql(DISPATCH_LEVEL,
				&OldIrql);
	if(MmIsAddressValid(AdressKeBugCheckEx)){
		//OldIrqlDpc=KeGetCurrentIrql();
		//KeRaiseIrql(HIGH_LEVEL,
				//&OldIrqlDpc);
		
		
		check=ExAllocatePoolWithTag(NonPagedPool,
									SizePagedBuffer,
									'TagP');
								
	 RtlCopyMemory(check,
					AdressKeBugCheckEx,
					SizePagedBuffer);
		
		
		KeBugPatch (opcodes0,opcodes1);
		//KeLowerIrql(OldIrqlDpc);
	} else{
		DbgPrint("Faild to test and  patch\n");
		}
	KeLowerIrql(OldIrql); 
	DbgPrint("We now have adresses of  before death functions!!!!!!!!!!!!!!!!!!");
}
VOID MyBugCheckFunc(){
	CONTEXT                       Context;
	//UNWIND_HISTORY_TABLE htable;
	__debugbreak();
	GetArgs();
	KdPrint(("KeBugCheck called\n"));
//	RtlCaptureContext(&GlobalContext);
	MyStackTrace64();
}
VOID EventFunc(){}

PUNWIND_HISTORY_TABLE 
MyStackTrace64()
{	NTSTATUS						Status;
	ULONG							OldProtection;
	//CONTEXT                       Context;
	KNONVOLATILE_CONTEXT_POINTERS NvContext;
	UNWIND_HISTORY_TABLE          UnwindHistoryTable;
	PRUNTIME_FUNCTION             RuntimeFunction;
	PVOID                         HandlerData;
	ULONG64                       EstablisherFrame;
	ULONG64                       ImageBase;
	ULONG						  Frame;
	ULONG i;

	static const CHAR* RegNames[ 16 ] =
		{ "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9",
		  "R10", "R11", "R12", "R13", "R14", "R15" };
	DbgPrint("StackTrace64: Executing stack trace...\n");
	


	RtlCaptureContext(&GlobalContext);

	

	RtlZeroMemory(
		&UnwindHistoryTable,
		sizeof(UNWIND_HISTORY_TABLE));

	//UnwindHistoryTable.Unwind = TRUE;

	//

	for ( Frame = 0;
		 Frame<12;
		 Frame++)
	{
		//
		
		//

		RuntimeFunction = RtlLookupFunctionEntry(
			GlobalContext.Rip,
			&ImageBase,
			&UnwindHistoryTable
			);
		
		
		
		RtlZeroMemory(
			&NvContext,
			sizeof(KNONVOLATILE_CONTEXT_POINTERS));

		if (!RuntimeFunction)
		{
			//
			
			//

			GlobalContext.Rip  = (ULONG64)(*(PULONG64)GlobalContext.Rsp);
			GlobalContext.Rsp += 8;
		}
		else
		{
			//
			

			RtlVirtualUnwind(
				0,
				ImageBase,
				GlobalContext.Rip,
				RuntimeFunction,
				&GlobalContext,
				&HandlerData,
				&EstablisherFrame,
				&NvContext);
		}

		//
		//if(Switcher==1){
		/*if((UnwindHistoryTable.Entry[Frame].ImageBase+UnwindHistoryTable.Entry[Frame].FunctionEntry->BeginAddress<Param2) && (Param2<UnwindHistoryTable.Entry[Frame].ImageBase+UnwindHistoryTable.Entry[Frame].FunctionEntry->EndAddress))
		{
			Status = NtProtectVirtualMemory(
					CurrprocHandle,
					&PtrAddress,
					&PtrAddressSize,
					PAGE_EXECUTE_READWRITE,
					&OldProtection 
				);
			if(!Status){
				DbgPrint("Fail to repair!\n");
			}	
			RtlRestoreContext(&GlobalContext,NULL);
		}*/
//}
		if (!GlobalContext.Rip)
			break;

		DbgPrint(
			"FRAME %02x: Eip=%p Esp=%p Ebp=%p\n",
			Frame,
			GlobalContext.Rip,
			GlobalContext.Rsp,
			GlobalContext.Rsp);
		DbgPrint(
			"r12=%p r13=%p r14=%p\n"
			"rdi=%p rsi=%p rbx=%p\n"
			"rbp=%p rsp=%p\n",
			GlobalContext.R12,
			GlobalContext.R13,
			GlobalContext.R14,
			GlobalContext.Rdi,
			GlobalContext.Rsi,
			GlobalContext.Rbx,
			GlobalContext.Rbp,
			GlobalContext.Rsp
			);

		/*static const CHAR* RegNames[ 16 ] =
		{ "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9",
		  "R10", "R11", "R12", "R13", "R14", "R15" };*/

		//
		
		//

		for ( i = 0;
			 i < 16;
			 i++)
		{
			if (NvContext.IntegerContext[ i ])
			{
				DbgPrint(
					" -> Saved register '%s' on stack at %p (=> %p)\n",
					RegNames[ i ],
					NvContext.IntegerContext[ i ],
					*NvContext.IntegerContext[ i ]);
			}
		}

		DbgPrint("\n");
	}

	//DbgBreakPoint();
	///RtlRestoreContext(&Context,NULL);

	return    &UnwindHistoryTable;;
}

