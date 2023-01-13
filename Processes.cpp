#include <windows.h>
#include <iostream>

using std::cout;
using std::endl;


void Hooking(PVOID, void*, DWORD, DWORD);
void Hooked();
void DoThis();
void (*ptrDoThis)() = DoThis;

int main(void)
{
	//I use the push ret hooking technic 
	const char* theHook = "\x68\x00\x00\x00\x00\xC3\xCC"; /* the 4 0x00 are here supposed to be
															 the address of the function I'm going to call in the hook*/

	HANDLE s = GetModuleHandle(0);//Getting image base address so I can find functions by offset
	Hooked(); //I call this function a first time to show what it does 
	Hooking((PVOID)((DWORD)s + 0x12566 /* find the address where the hooking take place by offset*/),
		(void*)theHook, 8, 7);

	Hooked();//I recall the function show it has been hooked

	std::cin.ignore();
	return 0;
}

void Hooking(PVOID overWritten, void* overWritting, DWORD noppingOut, DWORD overWrittingSz)
{
	DWORD oldProtect;
	DWORD old;
	VirtualProtect(overWritten, noppingOut, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(overWritting, overWrittingSz, PAGE_EXECUTE_READWRITE, &old);

	//I made 3 separated for loops because the address size are always 4 bytes 
	//and overWrittingSz and noppingOut can be different
	for (DWORD i = 1; i <= 4; i++)
		*(BYTE*)((DWORD)overWritting + i) = *(BYTE*)((DWORD)&ptrDoThis + i - 1);
	VirtualProtect(overWritting, overWrittingSz, old, &old);

	//Patching instructions with nops to not leave leftover bytes and break the function
	for (DWORD i = 0; i < noppingOut; i++)
	{
		//Saves the instructions so we can patch it back to 
		//normal but I take care of it properly later
		BYTE* instructionSaving = new BYTE[noppingOut];
		instructionSaving[i] = *(BYTE*)((DWORD)overWritten + i);

		*(BYTE*)((DWORD)overWritten + i) = 0x90;
	}

	for (DWORD i = 0; i < overWrittingSz; i++)
		*(BYTE*)((DWORD)overWritten + i) = *(BYTE*)((DWORD)overWritting + i);

	VirtualProtect(overWritten, noppingOut, oldProtect, &oldProtect);

	return;
}

void Hooked()
{
	cout << "print1" << endl;
	cout << "print2" << endl;
	cout << "print3" << endl;
	cout << "print4\n\n\n" << endl;

	return;
}

void __declspec (naked) DoThis()
{
	MessageBox(NULL, L"YOU HAVE BEEN VISITED BY THE CAPTAIN HOOK!", L"HACKED", MB_YESNO);

}