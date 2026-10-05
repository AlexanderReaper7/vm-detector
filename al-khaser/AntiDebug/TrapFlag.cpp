#include "pch.h"

#include "TrapFlag.h"

/*
	This technique is similar to exceptions based debugger detections.
	You enable the trap flag in the current process and check whether
	an exception is raised or not. If an exception is not raised, you
	can assume that a debugger has “swallowed” the exception for us,
	and that the program is being traced. The beauty of this approach
	is that it detects every debugger, user mode or kernel mode,
	because they all use the trap flag for tracing a program.

	Vectored Exception Handling is used here because SEH is an
	anti-debug trick in itself.
*/

static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		// VMProtect-style check: the single-step should land on the instruction
		// right after the trap flag is set, which here is a NOP (0x90). Verifying
		// the opcode at the exception address, not just that a single-step fired,
		// catches a debugger/VM that resumes stepping at the wrong address.
		BYTE opcode = *static_cast<BYTE*>(ExceptionInfo->ExceptionRecord->ExceptionAddress);
		if (opcode == 0x90)
			return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


// Optimization is disabled so the compiler keeps the NOPs in release builds;
// without this the single-step would not land on a 0x90 opcode.
#pragma optimize("", off)
BOOL TrapFlag()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;

	//  Set the trap flag, then single-step onto a known NOP opcode
	__writeeflags(__readeflags() | 0x100);
	__nop();
	__nop();

	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
#pragma optimize("", on)
