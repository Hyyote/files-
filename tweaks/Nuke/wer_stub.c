/*
 * wer_stub.c — Drop-in replacement for wer.dll
 * All exported WER APIs return success/no-op values.
 * 
 * Compile (MSVC):
 *   cl /c /O1 /GS- wer_stub.c
 *   link /dll /ENTRY:DllMain /DEF:wer_stub.def /NODEFAULTLIB kernel32.lib wer_stub.obj /out:wer.dll
 *
 * Compile (MinGW):
 *   gcc -shared -O2 -s -o wer.dll wer_stub.c wer_stub.def -lkernel32 -nostdlib -e DllMain
 */

#include <windows.h>

/* HRESULT codes */
#define WER_S_OK             ((HRESULT)0x00000000L)
#define WER_E_NOT_FOUND      ((HRESULT)0x80040001L)

/* Opaque handle type for WER reports */
typedef HANDLE HREPORT;

/* Minimal enum/struct stubs */
typedef enum _WER_REPORT_TYPE {
    WerReportNonCritical = 0,
    WerReportCritical = 1,
    WerReportApplicationCrash = 2,
    WerReportApplicationHang = 3,
    WerReportKernel = 4,
    WerReportInvalid
} WER_REPORT_TYPE;

typedef enum _WER_REPORT_UI {
    WerUIAdditionalDataDlgHeader = 1,
    WerUIIconFilePath = 2,
    WerUIConsentDlgHeader = 3,
    WerUIConsentDlgBody = 4,
    WerUIOnlineSolutionCheckText = 5,
    WerUIOfflineSolutionCheckText = 6,
    WerUICloseText = 7,
    WerUICloseDlgHeader = 8,
    WerUICloseDlgBody = 9,
    WerUICloseDlgButtonText = 10,
    WerUIMax
} WER_REPORT_UI;

typedef enum _WER_FILE_TYPE {
    WerFileTypeMicrodump = 1,
    WerFileTypeMinidump = 2,
    WerFileTypeHeapdump = 3,
    WerFileTypeUserDocument = 4,
    WerFileTypeOther = 5,
    WerFileTypeMax
} WER_FILE_TYPE;

typedef enum _WER_DUMP_TYPE {
    WerDumpTypeMicroDump = 1,
    WerDumpTypeMiniDump = 2,
    WerDumpTypeHeapDump = 3,
    WerDumpTypeTriageDump = 4,
    WerDumpTypeMax
} WER_DUMP_TYPE;

typedef enum _WER_SUBMIT_RESULT {
    WerReportQueued = 1,
    WerReportUploaded = 2,
    WerReportDebug = 3,
    WerReportFailed = 4,
    WerDisabled = 5,
    WerReportCancelled = 6,
    WerDisabledQueue = 7,
    WerReportAsync = 8,
    WerCustomAction = 9,
    WerThrottled = 10
} WER_SUBMIT_RESULT, *PWER_SUBMIT_RESULT;

typedef struct _WER_REPORT_INFORMATION {
    DWORD dwSize;
    HANDLE hProcess;
    WCHAR wzConsentKey[64];
    WCHAR wzFriendlyEventName[128];
    WCHAR wzApplicationName[128];
    WCHAR wzApplicationPath[MAX_PATH];
    WCHAR wzDescription[512];
    HWND hwndParent;
} WER_REPORT_INFORMATION, *PWER_REPORT_INFORMATION;

typedef struct _WER_EXCEPTION_INFORMATION {
    PEXCEPTION_POINTERS pExceptionPointers;
    BOOL bClientPointers;
} WER_EXCEPTION_INFORMATION, *PWER_EXCEPTION_INFORMATION;

typedef struct _WER_DUMP_CUSTOM_OPTIONS {
    DWORD dwSize;
    DWORD dwMask;
    DWORD dwDumpFlags;
    BOOL  bOnlyThisThread;
    DWORD dwExceptionThreadFlags;
    DWORD dwOtherThreadFlags;
    DWORD dwExceptionThreadExFlags;
    DWORD dwOtherThreadExFlags;
    DWORD dwPreferredModuleFlags;
    DWORD dwOtherModuleFlags;
    WCHAR wzPreferredModuleList[256];
} WER_DUMP_CUSTOM_OPTIONS, *PWER_DUMP_CUSTOM_OPTIONS;

/* ========================================================================= */
/*  DLL Entry Point                                                          */
/* ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}

/* ========================================================================= */
/*  Report Lifecycle APIs                                                    */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerReportCreate(
    PCWSTR pwzEventType,
    WER_REPORT_TYPE repType,
    PWER_REPORT_INFORMATION pReportInformation,
    HREPORT *phReportHandle)
{
    (void)pwzEventType; (void)repType; (void)pReportInformation;
    /* Return a dummy non-null handle so callers don't null-check fail */
    if (phReportHandle)
        *phReportHandle = (HREPORT)(ULONG_PTR)0xDEAD0001;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerReportSubmit(
    HREPORT hReportHandle,
    DWORD consent,
    DWORD dwFlags,
    PWER_SUBMIT_RESULT pSubmitResult)
{
    (void)hReportHandle; (void)consent; (void)dwFlags;
    if (pSubmitResult)
        *pSubmitResult = WerDisabled;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerReportCloseHandle(HREPORT hReportHandle)
{
    (void)hReportHandle;
    return WER_S_OK;
}

/* ========================================================================= */
/*  Report Data APIs                                                         */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerReportSetParameter(
    HREPORT hReportHandle,
    DWORD dwparamID,
    PCWSTR pwzName,
    PCWSTR pwzValue)
{
    (void)hReportHandle; (void)dwparamID; (void)pwzName; (void)pwzValue;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerReportAddFile(
    HREPORT hReportHandle,
    PCWSTR pwzPath,
    WER_FILE_TYPE repFileType,
    DWORD dwFileFlags)
{
    (void)hReportHandle; (void)pwzPath; (void)repFileType; (void)dwFileFlags;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerReportAddDump(
    HREPORT hReportHandle,
    HANDLE hProcess,
    HANDLE hThread,
    WER_DUMP_TYPE dumpType,
    PWER_EXCEPTION_INFORMATION pExceptionParam,
    PWER_DUMP_CUSTOM_OPTIONS pDumpCustomOptions,
    DWORD dwFlags)
{
    (void)hReportHandle; (void)hProcess; (void)hThread;
    (void)dumpType; (void)pExceptionParam; (void)pDumpCustomOptions; (void)dwFlags;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerReportSetUIOption(
    HREPORT hReportHandle,
    WER_REPORT_UI repUITypeID,
    PCWSTR pwzValue)
{
    (void)hReportHandle; (void)repUITypeID; (void)pwzValue;
    return WER_S_OK;
}

/* ========================================================================= */
/*  Global Configuration APIs                                                */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerSetFlags(DWORD dwFlags)
{
    (void)dwFlags;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerGetFlags(HANDLE hProcess, PDWORD pdwFlags)
{
    (void)hProcess;
    if (pdwFlags)
        *pdwFlags = 0;
    return WER_S_OK;
}

/* ========================================================================= */
/*  Application Exclusion APIs                                               */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerAddExcludedApplication(PCWSTR pwzExeName, BOOL bAllUsers)
{
    (void)pwzExeName; (void)bAllUsers;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRemoveExcludedApplication(PCWSTR pwzExeName, BOOL bAllUsers)
{
    (void)pwzExeName; (void)bAllUsers;
    return WER_S_OK;
}

/* ========================================================================= */
/*  Registration APIs                                                        */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerRegisterFile(
    PCWSTR pwzFile,
    WER_FILE_TYPE regFileType,
    DWORD dwFlags)
{
    (void)pwzFile; (void)regFileType; (void)dwFlags;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterFile(PCWSTR pwzFilePath)
{
    (void)pwzFilePath;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRegisterMemoryBlock(PVOID pvAddress, DWORD dwSize)
{
    (void)pvAddress; (void)dwSize;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterMemoryBlock(PVOID pvAddress)
{
    (void)pvAddress;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRegisterRuntimeExceptionModule(
    PCWSTR pwszOutOfProcessCallbackDll,
    PVOID pContext)
{
    (void)pwszOutOfProcessCallbackDll; (void)pContext;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterRuntimeExceptionModule(
    PCWSTR pwszOutOfProcessCallbackDll,
    PVOID pContext)
{
    (void)pwszOutOfProcessCallbackDll; (void)pContext;
    return WER_S_OK;
}

/* ========================================================================= */
/*  Additional APIs (Win8+/Win10+)                                           */
/* ========================================================================= */

__declspec(dllexport)
HRESULT WINAPI WerRegisterAdditionalProcess(DWORD processId, DWORD captureExtraInfoForThreadId)
{
    (void)processId; (void)captureExtraInfoForThreadId;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterAdditionalProcess(DWORD processId)
{
    (void)processId;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRegisterAppLocalDump(PCWSTR localAppDataRelativePath)
{
    (void)localAppDataRelativePath;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterAppLocalDump(void)
{
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRegisterExcludedMemoryBlock(const void *address, DWORD size)
{
    (void)address; (void)size;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterExcludedMemoryBlock(const void *address)
{
    (void)address;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerRegisterCustomMetadata(PCWSTR key, PCWSTR value)
{
    (void)key; (void)value;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerUnregisterCustomMetadata(PCWSTR key)
{
    (void)key;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerStoreOpen(DWORD repStoreType, PVOID *phReportStore)
{
    (void)repStoreType;
    if (phReportStore)
        *phReportStore = NULL;
    return WER_E_NOT_FOUND;
}

__declspec(dllexport)
void WINAPI WerStoreClose(PVOID hReportStore)
{
    (void)hReportStore;
}

__declspec(dllexport)
HRESULT WINAPI WerFreeString(PCWSTR pwszStr)
{
    (void)pwszStr;
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerStorePurge(void)
{
    return WER_S_OK;
}

__declspec(dllexport)
HRESULT WINAPI WerStoreGetFirstReportKey(PVOID hReportStore, PVOID *ppszReportKey)
{
    (void)hReportStore;
    if (ppszReportKey)
        *ppszReportKey = NULL;
    return WER_E_NOT_FOUND;
}

__declspec(dllexport)
HRESULT WINAPI WerStoreGetNextReportKey(PVOID hReportStore, PVOID *ppszReportKey)
{
    (void)hReportStore;
    if (ppszReportKey)
        *ppszReportKey = NULL;
    return WER_E_NOT_FOUND;
}
