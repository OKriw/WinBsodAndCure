#include "ntddk.h"
#include "PoolAlloc.h"
	
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
	KdPrint (("driver entry is finished\n"));
	KBSOD();

	return STATUS_SUCCESS;

};


NTSTATUS DriverControl(IN PDEVICE_OBJECT  pDeviceObject, __in PIRP irp){
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
					PoolAlloc();
					break;		
				case IOCTL_IF_POOL_WAS_PAGED:
					KdPrint (("IOCTL_IF_POOL_WAS_PAGED \n"));	
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
	KIRQL	OldIrql;
	NTSTATUS	Status;
	char*		TryToAcessPool;
	CONTEXT		TestContext;
	
	OldIrql=KeGetCurrentIrql();
	KeRaiseIrql(DISPATCH_LEVEL,
				&OldIrql);
	
	TryToAcessPool=(char*)PoolPtr;
	KdPrint(("We are going to fix Everything!\n"));
	KeLowerIrql(OldIrql);
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
			
		Status= MmProtectMdlSystemAddress(	PoolPtr,
											PAGE_READONLY);


}


BOOLEAN TestForSwap(PVOID PoolPtr){
	F1();
};

VOID 	F1(){
		RtlCaptureContext(&ContextF1);
		DbgPrint(
			"F1 Context : Rip=%p\n Esp=%p\n Ebp=%p\n",
			ContextF1.Rip,
			ContextF1.Rsp,
			ContextF1.Rsp);
DbgPrint(
			"r8=%p\n r9=%p\n r10=%p\n r11=%p\n r12=%p\n r13=%p\n r14=%p\n"
			"rdi=%p\n rsi=%p\n rbx=%p\n"
			"rbp=%p\n rsp=%p\n rax=%p\n rbx=%p\n rcx=%p rdx=%p\n\n",
			ContextF1.R8,
			ContextF1.R9,
			ContextF1.R10,
			ContextF1.R11,
			ContextF1.R12,
			ContextF1.R13,
			ContextF1.R14,
			ContextF1.Rdi,
			ContextF1.Rsi,
			ContextF1.Rbx,
			ContextF1.Rbp,
			ContextF1.Rsp,
			ContextF1.Rax,
			ContextF1.Rbx,
			ContextF1.Rcx,
			ContextF1.Rdx
			);
		F2();
}
VOID	F2(){
	SIZE_T TotalBytes = 4096;
	char* SomeTrash = "This is statment to poot in memory!";
	__debugbreak();
	SpoilContext();
	RtlCaptureContext(&ContextF2);
	RtlCopyMemory(	AddressPoolptr,
					SomeTrash,
					TotalBytes 
					);
}
NTSTATUS GetPage(PVOID PoolPtr){
	KdPrint(("We are gonna fix it, baby!\n"));
}

VOID DriverUnload(__in PDRIVER_OBJECT pDriverObject){
	UNICODE_STRING DosDeviceName;
	KeDeregisterBugCheckCallback(BugCheckDataPool);
	KdPrint (("fakedevice: Unload\n"));
	RtlInitUnicodeString( &DosDeviceName, DOS_DEVICE_NAME );
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
    AdressKeBugCheckEx=MmGetSystemRoutineAddress(& KeBugCheckExAdress);
	DbgPrint("KeBugCheckExAdress = %p\n",AdressKeBugCheckEx);
	
	opcodes0=(UINT64)AdressKeBugCheckEx;
	opcodes1=(UINT64)&MyBugCheckFunc; 
	//48Ba  92E4 6701 00F8 FFFF  FFd2
	OldIrql=KeGetCurrentIrql();
	KeRaiseIrql(DISPATCH_LEVEL,
				&OldIrql);
	if(MmIsAddressValid(AdressKeBugCheckEx)){
		check=ExAllocatePoolWithTag(NonPagedPool,
									SizePagedBuffer,
									'TagP');
								
	 RtlCopyMemory(check,
					AdressKeBugCheckEx,
					SizePagedBuffer);
		
		
		KeBugPatch (opcodes0,opcodes1);
	} else{
		DbgPrint("Faild to test and  patch\n");
		}
	KeLowerIrql(OldIrql); 
	DbgPrint("We now have adresses of  before death functions!!!!!!!!!!!!!!!!!!");
}
VOID MyBugCheckFunc(){
	CONTEXT		Context;
	GetArgs();
	KdPrint(("KeBugCheck called\n"));
	MyStackTrace64();
}
//VOID EventFunc(){}

PUNWIND_HISTORY_TABLE 
MyStackTrace64()
{	NTSTATUS						Status;
	KIRQL							Irql;
	ULONG							OldProtection;
	KNONVOLATILE_CONTEXT_POINTERS NvContext;
	UNWIND_HISTORY_TABLE          UnwindHistoryTable;
	PRUNTIME_FUNCTION             RuntimeFunction;
	PVOID                         HandlerData;
	ULONG64                       EstablisherFrame;
	ULONG64                       ImageBase;
	ULONG						  Frame;
	ULONG i;
	CONTEXT						LocalContext;
	ULONG64						RAXs=0;
	ULONG64						RCXs=0;
	ULONG64						RDXs=0;
	ULONG64						R8s=0;
	ULONG64						R9s=0;
	ULONG64						R10s=0;
	ULONG64						R11s=0;
	ULONG64						RBPs=0;
	ULONG64						TrapFramess=0;
	static const CHAR* RegNames[ 16 ] =
		{ "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9",
		  "R10", "R11", "R12", "R13", "R14", "R15" };
	DbgPrint("StackTrace64: Executing stack trace...\n");
	RtlCaptureContext(&GlobalContext);
	LocalContext=GlobalContext;
	RtlZeroMemory(&UnwindHistoryTable,
		sizeof(UNWIND_HISTORY_TABLE));
//frame walk
	for ( Frame = 0;Frame<12;Frame++){
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
			GlobalContext.Rip  = (ULONG64)(*(PULONG64)GlobalContext.Rsp);
			GlobalContext.Rsp += 8;
		}
		else
		{
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
		if(Frame==3){
			Irql=KeGetCurrentIrql();
			RBPs=GlobalContext.Rbp;
			TrapFramess=(RBPs-0x80);
			RAXs=*(PULONG64)(RBPs-0x50);
			RCXs=*(PULONG64)(RBPs-0x48);
			RDXs=*(PULONG64)(RBPs-0x40);
			R8s=*(PULONG64)(RBPs-0x38);
			R9s=*(PULONG64)(RBPs-0x30);
			R10s=*(PULONG64)(RBPs-0x28);
			R11s=*(PULONG64)(RBPs-0x20);
			
			Status= MmProtectMdlSystemAddress(
							PoolPtr,
							PAGE_READWRITE);
		}
		if(Frame==4){
			Irql=KeGetCurrentIrql();
			GlobalContext.Rax=RAXs;
			GlobalContext.Rcx=RCXs;
			GlobalContext.Rdx=RDXs;
			GlobalContext.R8=R8s;
			GlobalContext.R9=R9s;
			GlobalContext.R10=R10s;
			GlobalContext.R11=R11s;
			Status= MmProtectMdlSystemAddress(
							PoolPtr,
							PAGE_READWRITE);
			PushLock();				
			RtlRestoreContext(&GlobalContext,NULL);
			break;
		}
		if (!GlobalContext.Rip)
			break;

		DbgPrint(
			"FRAME %02x: Rip=%p Rsp=%p Rbp=%p \n",
			Frame,
			GlobalContext.Rip,
			GlobalContext.Rsp,
			GlobalContext.Rsp);
		DbgPrint(
			"r8=%p\n r9=%p\n r10=%p\n r11=%p\n r12=%p\n r13=%p\n r14=%p\n"
			"rdi=%p\n rsi=%p\n rbx=%p\n"
			"rbp=%p\n rsp=%p\n rax=%p\n rbx=%p\n rcx=%p rdx=%p\n\n",
			GlobalContext.R8,
			GlobalContext.R9,
			GlobalContext.R10,
			GlobalContext.R11,
			GlobalContext.R12,
			GlobalContext.R13,
			GlobalContext.R14,
			GlobalContext.Rdi,
			GlobalContext.Rsi,
			GlobalContext.Rbx,
			GlobalContext.Rbp,
			GlobalContext.Rsp,
			GlobalContext.Rax,
			GlobalContext.Rbx,
			GlobalContext.Rcx,
			GlobalContext.Rdx
			);
		for ( i = 0;i < 16;i++){
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

	while(1){}

	return    &UnwindHistoryTable;;
}

