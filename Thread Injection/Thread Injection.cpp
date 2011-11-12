#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <WinNT.h>

using namespace std;

struct partialTIB
{
	DWORD SEHFrame;
	DWORD StackTopPointer;
	DWORD StackBottomPointer;
	DWORD Unknown;
	DWORD FiberData;
	DWORD ArbitraryDataSlot;
	DWORD LinearAddressOfTIB;
	DWORD EnviromentPointer;
	DWORD ProcessID;
	DWORD CurrentThreadID;
};


partialTIB GetProcessThreadInformation(DWORD procID)
{
    DWORD pointerTID;

    _asm
	{
	   MOV EAX, FS:[0x18]
	   MOV [pointerTID], EAX
    }

	partialTIB TIB;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, false, procID);
    ReadProcessMemory(hProcess, (LPVOID)pointerTID, &TIB, sizeof(partialTIB), NULL);
    CloseHandle(hProcess);

    return TIB;
}

HANDLE OpenAndSuspendThread(DWORD threadID)
{
	DWORD ACCESS =
		THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;
	HANDLE thread = OpenThread(ACCESS, false, threadID);
	SuspendThread(thread);
	return thread;
}

LPVOID CreateCodeCave(HANDLE process, DWORD InstructPtr)
{
	LPVOID codeCave =
		VirtualAllocEx(process, NULL, 6, 
					MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	DWORD push = 0x68;
	DWORD retn = 0xC3;
	
	WriteProcessMemory(process, codeCave, &push, 1, NULL); // "PUSH" opcode
	WriteProcessMemory(process, (LPVOID)((DWORD)codeCave+1), &InstructPtr, 4, NULL); //return address
	WriteProcessMemory(process, (LPVOID)((DWORD)codeCave+5), &retn, 4, NULL); //"RETN" opcode

	return codeCave;
}

CONTEXT RetriveThreadControlContext(HANDLE thread)
{
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(thread, &threadContext);
	return threadContext;
}

DWORD FindProcessByWindowName(char* windowName)
{
	DWORD procID = NULL;
	HWND window = FindWindowA(NULL, windowName);

	if (window)
		GetWindowThreadProcessId(window, &procID);

	return procID;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD procID = NULL;

	while (!procID)
	{
		char windowTitle[128];
		cout << "Enter the title of the window to inject the code into:" << endl;
		cin >> windowTitle;
		cout << endl;
		procID = FindProcessByWindowName(windowTitle);
	}
	
	partialTIB TIB = GetProcessThreadInformation(procID);
	cout << "Detected process: " << TIB.ProcessID << endl;
	cout << "Detected main thread: " << TIB.CurrentThreadID << endl;


	HANDLE thread = OpenAndSuspendThread(TIB.CurrentThreadID);
	CONTEXT threadContext = RetriveThreadControlContext(thread);
	cout << "Thread Instruction Pointer: " << threadContext.Eip << endl;

	HANDLE process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, TIB.ProcessID);
	cout << "Writing codecave..." << endl;
	LPVOID codeCave = CreateCodeCave(process, threadContext.Eip);
	cout << "Codecave pointer: " << (DWORD)codeCave << endl;

	threadContext.Eip = (DWORD)codeCave;
	cout << "Spoofing EIP register..." << endl;

	threadContext.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(thread, &threadContext);

	cout << "Resuming thread..." << endl;
	ResumeThread(thread);
	cout << "DONE!" << endl;
	Sleep(2000);

	VirtualFreeEx(process, codeCave, 6, MEM_DECOMMIT);
	CloseHandle(process);
	CloseHandle(thread);


	while (true)
		Sleep(100);
	return 0;
}