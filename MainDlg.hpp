// MainDlg.h : interface of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once
#include <fstream>
#include <string>
#include <time.h>

#include "resource.h"
#include "./pe_lib/pe_bliss.h"

#if defined(_DEBUG)
#pragma comment(lib,"./Debug/pe_bliss.lib")
#else
#pragma comment(lib,"./Release/pe_bliss.lib")
#endif

using namespace pe_bliss;

class CMainDlg : public CDialogImpl<CMainDlg>, public CUpdateUI<CMainDlg>,
	public CMessageFilter, public CIdleHandler
{
public:
	enum { IDD = IDD_MAINDLG };

	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		return CWindow::IsDialogMessage(pMsg);
	}

	virtual BOOL OnIdle()
	{
		UIUpdateChildWindows();
		return FALSE;
	}

	BEGIN_UPDATE_UI_MAP(CMainDlg)
	END_UPDATE_UI_MAP()

	BEGIN_MSG_MAP(CMainDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
		MESSAGE_HANDLER(WM_CLOSE, OnClose)
		MESSAGE_HANDLER(WM_DROPFILES, OnDropFile)

		COMMAND_ID_HANDLER(IDC_MAKE, OnDoMake)
		COMMAND_ID_HANDLER(IDC_EXIT, OnExit)
		COMMAND_ID_HANDLER(IDC_BrowserFile1, OnBrowserFile1)
		COMMAND_ID_HANDLER(IDC_BrowserFile2, OnBrowserFile2)
	END_MSG_MAP()

	// Handler prototypes (uncomment arguments if needed):
	//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	std::wstring		g_targetFile;
	std::wstring		g_sourceFile;
	std::wstring		g_masmFile;
	BOOL				isx64 = FALSE;

	LRESULT DebugMessage(char *format, ...)
	{

		char buf[1024] = { 0 };
		va_list varArgs;
		va_start(varArgs, format);

		vsnprintf(buf, sizeof(buf), format, varArgs);

		va_end(varArgs);

		strcat(buf, "\r\n");
		::SendDlgItemMessageA(m_hWnd, IDC_EDIT3, EM_SETSEL, WPARAM(0x88888), LPARAM(0x88888));
		::SendDlgItemMessageA(m_hWnd, IDC_EDIT3, EM_REPLACESEL, NULL, (LPARAM)buf);

		return TRUE;

	}

	std::wstring AsciiToUnicode(const std::string& str) {
		// Ԥ��-�������п��ֽڵĳ���    
		int unicodeLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
		// ��ָ�򻺳�����ָ����������ڴ�    
		wchar_t *pUnicode = (wchar_t*)malloc(sizeof(wchar_t)*unicodeLen);
		// ��ʼ�򻺳���ת���ֽ�    
		MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, pUnicode, unicodeLen);
		std::wstring ret_str = pUnicode;
		free(pUnicode);
		return ret_str;
	}

	std::string UnicodeToAscii(const std::wstring& wstr) {
		// Ԥ��-�������ж��ֽڵĳ���    
		int ansiiLen = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
		// ��ָ�򻺳�����ָ����������ڴ�    
		char *pAssii = (char*)malloc(sizeof(char)*ansiiLen);
		// ��ʼ�򻺳���ת���ֽ�    
		WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, pAssii, ansiiLen, nullptr, nullptr);
		std::string ret_str = pAssii;
		free(pAssii);
		return ret_str;
	}

	BOOL DoWriteFile(WCHAR *path, std::wstring &data)
	{
		BOOL		result = FALSE;
		HANDLE		hFile;
		DWORD		written = 0;
		std::string	wdata;

		hFile = CreateFile(path,
							GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
							NULL,
							CREATE_ALWAYS, 
							FILE_ATTRIBUTE_NORMAL, 
							NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}

		wdata = UnicodeToAscii(data);

		result = WriteFile(hFile, wdata.data(), wdata.size(), &written, NULL);

		CloseHandle(hFile);

		return result;

	}

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// center the dialog on the screen
		CenterWindow();

		// set icons
		HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
		SetIcon(hIcon, TRUE);
		HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
		SetIcon(hIconSmall, FALSE);

		// register object for message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->AddMessageFilter(this);
		pLoop->AddIdleHandler(this);

		UIAddChildWindowContainer(m_hWnd);

		return TRUE;
	}

	LRESULT OnDoMake(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		WCHAR		fileAsmPath[MAX_PATH];
		WCHAR		fileCppPath[MAX_PATH];

		GetDlgItemText(IDC_EDIT2, fileCppPath, MAX_PATH);

		if (DoWriteFile(fileCppPath, g_sourceFile) == FALSE)
		{
			MessageBox(fileCppPath, L"Fail!", MB_ICONERROR);
			return 0;
		}

		if (isx64)
		{
			wcscpy(fileAsmPath, fileCppPath);
			PathRemoveExtension(fileAsmPath);
			wcscat(fileAsmPath, L"_jump.asm");

			if (DoWriteFile(fileAsmPath, g_masmFile) ==FALSE)
			{
				MessageBox( fileAsmPath, L"Fail!", MB_ICONERROR);
				return 0;
			}
			
		}

		MessageBox(L"ok", L"info", MB_ICONINFORMATION);
		return 0;
	}

	LRESULT OnCheckFile(WCHAR *wcsFilePath)
	{
		CHAR		filePath[MAX_PATH];
		WCHAR		fileShortName[MAX_PATH];

		//
		//��������
		//
		g_sourceFile.clear();
		g_masmFile.clear();
		g_targetFile.clear();
		isx64 = FALSE;
 
		//
		//�õ��ļ���
		//
		wcscpy(fileShortName, wcsFilePath);
		PathStripPath(fileShortName);
		g_targetFile = fileShortName;

		SHUnicodeToAnsi(wcsFilePath, filePath, MAX_PATH);

		try
		{
			WCHAR						tipsMessage[512];
			std::ifstream				pe_file(filePath, std::ios::in | std::ios::binary);

			pe_base						image(pe_factory::create_pe(pe_file));
			std::wstring				showExports;

			export_info					info;
			exported_functions_list		exports;

			uint64_t					timestamp;
			struct tm					*tblock;

			//
			//�Ƿ���� ������
			//
			if (!image.has_exports())
			{
				MessageBox(L"EXPORT_TABLE is not exist", L"info", MB_ICONERROR);
				return FALSE;
			}
			//
			//��ȡ��������
			//
			exports = get_exported_functions(image, info);

			//
			//��ʾ�����ַ���
			//
			SetDlgItemTextA(m_hWnd, IDC_NAMESTRING, info.get_name().c_str());

			//
			//��ʾ����ƽ̨
			//
			if (image.get_machine() == IMAGE_FILE_MACHINE_I386)
			{
				SetDlgItemText(IDC_Architecture, L"IMAGE_FILE_MACHINE_I386");
			}
			else if (image.get_machine() == IMAGE_FILE_MACHINE_AMD64)
			{
				isx64 = TRUE;
				SetDlgItemText(IDC_Architecture, L"IMAGE_FILE_MACHINE_AMD64");
			}
			else if (image.get_machine() == IMAGE_FILE_MACHINE_IA64)
			{
				isx64 = TRUE;
				SetDlgItemText(IDC_Architecture, L"IMAGE_FILE_MACHINE_IA64");
			}
			else
			{
				wsprintf(tipsMessage, L"machine = (0x%x)", image.get_machine());
				SetDlgItemText(IDC_Architecture, tipsMessage);
			}

			//
			//��ʾʱ���
			//
			timestamp = image.get_time_date_stamp();
			tblock = localtime((const time_t*)&timestamp);
			SetDlgItemTextA(m_hWnd, IDC_Timestamp, asctime(tblock));


			//
			//��ӡ�����������
			//
			SetDlgItemTextA(m_hWnd, IDC_EDIT3, "");
			for (auto funcname : exports)
			{
				wsprintf(tipsMessage,L"%-4d %S\r\n",
							 funcname.get_ordinal(),
							 funcname.has_name() ? funcname.get_name().c_str() : "N/A");
				showExports += tipsMessage;
			}
			SetDlgItemText(IDC_EDIT3, showExports.c_str());

			//
			//����cpp�ļ�
			//

			if (isx64)
			{
				//
				//������.asm �ļ� 
				//
				{
					//
					//������ʾ��Ϣ
					//
					g_masmFile += L";Created by AheadLib x86/x64 v1.0\r\n";
					g_masmFile += L";ml64 /Fo $(IntDir)%(fileName).obj /c %(fileName).asm\r\n";
					g_masmFile += L";$(IntDir)%(fileName).obj;%(Outputs)\r\n\r\n";

					//
					//���� dataȫ�ֺ���ָ��
					//
					g_masmFile += L"\r\n.DATA\r\n";

					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									  L"EXTERN pfnAheadLib_%S:dq;\r\n",
									  funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									  L"EXTERN pfnAheadLib_Unnamed%d:dq;\r\n",
									  funcname.get_ordinal());
						}
						g_masmFile += tipsMessage;
					}

					//
					//���ɴ����
					//
					g_masmFile += L"\r\n.CODE\r\n";

					for (auto funcname : exports)
					{
						std::string	it = funcname.get_name();
						uint16_t	ordit = funcname.get_ordinal();
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									  L"AheadLib_%S PROC\r\n"
									  L" jmp pfnAheadLib_%S\r\n"
									  L"AheadLib_%S ENDP\r\n\r\n",
									  it.c_str(),
									  it.c_str(),
									  it.c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									  L"AheadLib_Unnamed%d PROC\r\n"
									  L" jmp pfnAheadLib_Unnamed%d\r\n"
									  L"AheadLib_Unnamed%d ENDP\r\n\r\n",
									  ordit,
									  ordit,
									  ordit);
						}
						g_masmFile += tipsMessage;
					}


					//
					//�������
					//
					g_masmFile += L"\r\nEND\r\n";
				}

				//
				//������Դ�ļ�
				//
				{
					//
					//����ͷ�ļ�����
					//
					g_sourceFile += L"//Created by AheadLib x86/x64 v1.0\r\n";
					g_sourceFile += L"#include <windows.h>\r\n";
					g_sourceFile += L"#include <Shlwapi.h>\r\n";
					g_sourceFile += L"#pragma comment( lib, \"Shlwapi.lib\")\r\n\r\n";

					//
					//����linkr exports
					//
					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									  L"#pragma comment(linker, \"/EXPORT:%S=AheadLib_%S,@%d\")\r\n",
									  funcname.get_name().c_str(),
									  funcname.get_name().c_str(),
									  funcname.get_ordinal());
						}
						else
						{
							wsprintf(tipsMessage,
									 L"#pragma comment(linker, \"/EXPORT:Noname%d=AheadLib_Unnamed%d,@%d,NONAME\")\r\n",
									  funcname.get_ordinal(),
									  funcname.get_ordinal(),
									  funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					//
					//����ȫ�ֱ���
					//
					g_sourceFile += L"extern \"C\" {\r\n";

					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									  L" PVOID pfnAheadLib_%S;\r\n",
									  funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									  L" PVOID pfnAheadLib_Unnamed%d;\r\n",
									  funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									 L" void AheadLib_%S(void);\r\n",
									  funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									 L" void AheadLib_Unnamed%d(void);\r\n",
									  funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}


					g_sourceFile += L"};\r\n\r\n";

					//
					//����ȫ�ֱ���
					//
					g_sourceFile += L"static HMODULE	g_OldModule = NULL;\r\n\r\n";

					//
					//Load()
					//
					g_sourceFile += L"// ����ԭʼģ��\r\n";
					g_sourceFile += L"__inline BOOL WINAPI Load()\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	TCHAR tzPath[MAX_PATH];\r\n";
					g_sourceFile += L"	TCHAR tzTemp[MAX_PATH * 2];\r\n";
					g_sourceFile += L"	GetSystemDirectory(tzPath, MAX_PATH);\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	lstrcat(tzPath, TEXT(\"\\\\";
					g_sourceFile += g_targetFile.c_str();
					g_sourceFile += L"\"));\r\n";
					g_sourceFile += L"	g_OldModule = LoadLibrary(tzPath);\r\n";
					g_sourceFile += L"	if (g_OldModule == NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		wsprintf(tzTemp, TEXT(\"�޷��ҵ����� %s,�����޷���������\"), tzPath);\r\n";
					g_sourceFile += L"		MessageBox(NULL, tzTemp, TEXT(\"AheadLib\"), MB_ICONSTOP);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	return (g_OldModule != NULL);	\r\n";
					g_sourceFile += L"}\r\n\r\n";

					//
					//Free()
					//
					g_sourceFile += L"// �ͷ�ԭʼģ��\r\n";
					g_sourceFile += L"__inline VOID WINAPI Free()\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	if (g_OldModule)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		FreeLibrary(g_OldModule);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"}\r\n";

					//
					//GetAddress()
					//
					g_sourceFile += L"// ��ȡԭʼ������ַ\r\n";
					g_sourceFile += L"FARPROC WINAPI GetAddress(PCSTR pszProcName)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	FARPROC fpAddress;\r\n";
					g_sourceFile += L"	CHAR szProcName[128];\r\n";
					g_sourceFile += L"	TCHAR tzTemp[MAX_PATH];\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	fpAddress = GetProcAddress(g_OldModule, pszProcName);\r\n";
					g_sourceFile += L"	if (fpAddress == NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		if (HIWORD(pszProcName) == 0)\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			wsprintfA(szProcName, \"%d\", pszProcName);\r\n";
					g_sourceFile += L"			pszProcName = szProcName;\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"		wsprintf(tzTemp, TEXT(\"�޷��ҵ����� %s,�����޷���������\"), pszProcName);\r\n";
					g_sourceFile += L"		MessageBox(NULL, tzTemp, TEXT(\"AheadLib\"), MB_ICONSTOP);\r\n";
					g_sourceFile += L"		ExitProcess(-2);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	return fpAddress;\r\n";
					g_sourceFile += L"}\r\n\r\n";

					//
					//Init()
					//
					g_sourceFile += L"// ��ʼ����ȡԭ������ַ\r\n";
					g_sourceFile += L"BOOL WINAPI Init()\r\n";
					g_sourceFile += L"{\r\n";

					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									  L"	if(NULL == (pfnAheadLib_%S = GetAddress(\"%S\")))\r\n		return FALSE;\r\n",
									  funcname.get_name().c_str(),
									  funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									  L"	if(NULL == (pfnAheadLib_Unnamed%d = GetAddress(MAKEINTRESOURCEA(%d))))\r\n		return FALSE;\r\n",
									  funcname.get_ordinal(),
									  funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n\r\n";


					//
					//����patch�̴߳���
					//
					g_sourceFile += L"DWORD WINAPI ThreadProc(LPVOID lpThreadParameter)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	PVOID			addr1 = reinterpret_cast<PVOID>(0x00401000);\r\n";
					g_sourceFile += L"	unsigned char	data1[] = { 0x90, 0x90, 0x90, 0x90 };\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	HANDLE			hProcess;\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	//\r\n";
					g_sourceFile += L"	//�ƹ�VMP3.x ���ϰ汾�� �ڴ����Ա���\r\n";
					g_sourceFile += L"	//\r\n";
					g_sourceFile += L"	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());\r\n";
					g_sourceFile += L"	if (hProcess != NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		WriteProcessMemory(hProcess, addr1, data1, sizeof(data1), NULL);\r\n";
					g_sourceFile += L"		CloseHandle(hProcess);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n\r\n";



					//
					//����DllMain
					//
					g_sourceFile += L"BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	if (dwReason == DLL_PROCESS_ATTACH)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		DisableThreadLibraryCalls(hModule);\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"		if(Load() && Init())\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			TCHAR szAppName[MAX_PATH]  = TEXT(\"MyApp.exe\");	//���Ϊ��Ӧ��Dll�����ļ���\r\n";
					g_sourceFile += L"			TCHAR szFullPath[MAX_PATH] = {0};\r\n";
					g_sourceFile += L"			int nLength = 0;\r\n";
					g_sourceFile += L"			nLength = GetModuleFileName(NULL, szFullPath, MAX_PATH);\r\n";
					g_sourceFile += L"			PathStripPath(szFullPath);\r\n";
					g_sourceFile += L"			if (StrCmpI(szAppName, szFullPath) == 0 || TRUE)//�����Ƿ��ж�����������?\r\n";
					g_sourceFile += L"			{\r\n";
					g_sourceFile += L"				::CreateThread(NULL, NULL, ThreadProc, NULL, NULL, NULL);//�򲹶��߳�\r\n";
					g_sourceFile += L"			}\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"		else\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			return FALSE;\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	else if (dwReason == DLL_PROCESS_DETACH)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		Free();\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n";

				}

			}
			else //x86�ļ�����
			{
				//
				//����x86Դ�ļ�
				//
				{
					//
					//����ͷ�ļ�����
					//
					g_sourceFile += L"//Created by AheadLib x86/x64 v1.0\r\n";
					g_sourceFile += L"#include <windows.h>\r\n";
					g_sourceFile += L"#include <Shlwapi.h>\r\n";
					g_sourceFile += L"#pragma comment( lib, \"Shlwapi.lib\")\r\n\r\n";


					//
					//����linkr exports
					//
					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									 L"#pragma comment(linker, \"/EXPORT:%S=_AheadLib_%S,@%d\")\r\n",
									 funcname.get_name().c_str(),
									 funcname.get_name().c_str(),
									 funcname.get_ordinal());
						}
						else
						{
							wsprintf(tipsMessage,
									 L"#pragma comment(linker, \"/EXPORT:Noname%d=_AheadLib_Unnamed%d,@%d,NONAME\")\r\n",
									 funcname.get_ordinal(),
									 funcname.get_ordinal(),
									 funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					//
					//����ȫ�ֱ���
					//


					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									 L"PVOID pfnAheadLib_%S;\r\n",
									 funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									 L"PVOID pfnAheadLib_Unnamed%d;\r\n",
									 funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					g_sourceFile += L"\r\n\r\n";

					//
					//����ȫ�ֱ���
					//
					g_sourceFile += L"static HMODULE	g_OldModule = NULL;\r\n\r\n";

					//
					//Load()
					//
					g_sourceFile += L"// ����ԭʼģ��\r\n";
					g_sourceFile += L"__inline BOOL WINAPI Load()\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	TCHAR tzPath[MAX_PATH];\r\n";
					g_sourceFile += L"	TCHAR tzTemp[MAX_PATH * 2];\r\n";
					g_sourceFile += L"	GetSystemDirectory(tzPath, MAX_PATH);\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	lstrcat(tzPath, TEXT(\"\\\\";
					g_sourceFile += g_targetFile.c_str();
					g_sourceFile += L"\"));\r\n";
					g_sourceFile += L"	g_OldModule = LoadLibrary(tzPath);\r\n";
					g_sourceFile += L"	if (g_OldModule == NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		wsprintf(tzTemp, TEXT(\"�޷��ҵ����� %s,�����޷���������\"), tzPath);\r\n";
					g_sourceFile += L"		MessageBox(NULL, tzTemp, TEXT(\"AheadLib\"), MB_ICONSTOP);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	return (g_OldModule != NULL);	\r\n";
					g_sourceFile += L"}\r\n\r\n";

					//
					//Free()
					//
					g_sourceFile += L"// �ͷ�ԭʼģ��\r\n";
					g_sourceFile += L"__inline VOID WINAPI Free()\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	if (g_OldModule)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		FreeLibrary(g_OldModule);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"}\r\n";

					//
					//GetAddress()
					//
					g_sourceFile += L"// ��ȡԭʼ������ַ\r\n";
					g_sourceFile += L"FARPROC WINAPI GetAddress(PCSTR pszProcName)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	FARPROC fpAddress;\r\n";
					g_sourceFile += L"	CHAR szProcName[128];\r\n";
					g_sourceFile += L"	TCHAR tzTemp[MAX_PATH];\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	fpAddress = GetProcAddress(g_OldModule, pszProcName);\r\n";
					g_sourceFile += L"	if (fpAddress == NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		if (HIWORD(pszProcName) == 0)\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			wsprintfA(szProcName, \"%d\", pszProcName);\r\n";
					g_sourceFile += L"			pszProcName = szProcName;\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"		wsprintf(tzTemp, TEXT(\"�޷��ҵ����� %s,�����޷���������\"), pszProcName);\r\n";
					g_sourceFile += L"		MessageBox(NULL, tzTemp, TEXT(\"AheadLib\"), MB_ICONSTOP);\r\n";
					g_sourceFile += L"		ExitProcess(-2);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	return fpAddress;\r\n";
					g_sourceFile += L"}\r\n\r\n";

					//
					//Init()
					//
					g_sourceFile += L"// ��ʼ����ȡԭ������ַ\r\n";
					g_sourceFile += L"BOOL WINAPI Init()\r\n";
					g_sourceFile += L"{\r\n";

					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									 L"	if(NULL == (pfnAheadLib_%S = GetAddress(\"%S\")))\r\n		return FALSE;\r\n",
									 funcname.get_name().c_str(),
									 funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									 L"	if(NULL == (pfnAheadLib_Unnamed%d = GetAddress(MAKEINTRESOURCEA(%d))))\r\n		return FALSE;\r\n",
									 funcname.get_ordinal(),
									 funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}

					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n\r\n";


					//
					//����patch�̴߳���
					//
					g_sourceFile += L"DWORD WINAPI ThreadProc(LPVOID lpThreadParameter)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	PVOID			addr1 = reinterpret_cast<PVOID>(0x00401000);\r\n";
					g_sourceFile += L"	unsigned char	data1[] = { 0x90, 0x90, 0x90, 0x90 };\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	HANDLE			hProcess;\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	//\r\n";
					g_sourceFile += L"	//�ƹ�VMP3.x ���ϰ汾�� �ڴ����Ա���\r\n";
					g_sourceFile += L"	//\r\n";
					g_sourceFile += L"	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());\r\n";
					g_sourceFile += L"	if (hProcess != NULL)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		WriteProcessMemory(hProcess, addr1, data1, sizeof(data1), NULL);\r\n";
					g_sourceFile += L"		CloseHandle(hProcess);\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n\r\n";



					//
					//����DllMain
					//
					g_sourceFile += L"BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)\r\n";
					g_sourceFile += L"{\r\n";
					g_sourceFile += L"	if (dwReason == DLL_PROCESS_ATTACH)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		DisableThreadLibraryCalls(hModule);\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"		if(Load() && Init())\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			TCHAR szAppName[MAX_PATH]  = TEXT(\"MyApp.exe\");	//���Ϊ��Ӧ��Dll�����ļ���\r\n";
					g_sourceFile += L"			TCHAR szFullPath[MAX_PATH] = {0};\r\n";
					g_sourceFile += L"			int nLength = 0;\r\n";
					g_sourceFile += L"			nLength = GetModuleFileName(NULL, szFullPath, MAX_PATH);\r\n";
					g_sourceFile += L"			PathStripPath(szFullPath);\r\n";
					g_sourceFile += L"			if (StrCmpI(szAppName, szFullPath) == 0 || TRUE)//�����Ƿ��ж�����������?\r\n";
					g_sourceFile += L"			{\r\n";
					g_sourceFile += L"				::CreateThread(NULL, NULL, ThreadProc, NULL, NULL, NULL);//�򲹶��߳�\r\n";
					g_sourceFile += L"			}\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"		else\r\n";
					g_sourceFile += L"		{\r\n";
					g_sourceFile += L"			return FALSE;\r\n";
					g_sourceFile += L"		}\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"	else if (dwReason == DLL_PROCESS_DETACH)\r\n";
					g_sourceFile += L"	{\r\n";
					g_sourceFile += L"		Free();\r\n";
					g_sourceFile += L"	}\r\n";
					g_sourceFile += L"\r\n";
					g_sourceFile += L"	return TRUE;\r\n";
					g_sourceFile += L"}\r\n\r\n";

					//
					//������ת����
					//
					
					g_sourceFile += L" // ��������\r\n";
					for (auto funcname : exports)
					{
						if (funcname.has_name())
						{
							wsprintf(tipsMessage,
									 L"EXTERN_C __declspec(naked) void __cdecl AheadLib_%S(void)\r\n"
									 L"{\r\n"
									 L"	__asm jmp pfnAheadLib_%S;\r\n"
									 L"}\r\n\r\n",
									 funcname.get_name().c_str(),
									 funcname.get_name().c_str());
						}
						else
						{
							wsprintf(tipsMessage,
									 L"EXTERN_C __declspec(naked) void __cdecl AheadLib_Unnamed%d(void)\r\n"
									 L"{\r\n"
									 L"	__asm jmp pfnAheadLib_Unnamed%d;\r\n"
									 L"}\r\n\r\n",
									 funcname.get_ordinal(),
									 funcname.get_ordinal());
						}
						g_sourceFile += tipsMessage;
					}


				}

			}
		



		}
		catch (const pe_exception& e)
		{
			MessageBoxA(m_hWnd, e.what(), "info", MB_ICONERROR);
			return FALSE;
		}
		return TRUE;
	}

	LRESULT OnBrowserFile1(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CFileDialog		filedlg(TRUE,
								NULL,
								NULL,
								NULL,
								L"Dynamic Link Library(*.dll)\0*.dll\0All Files(*.*)\0*.*\0\0",
								this->m_hWnd);

		if (filedlg.DoModal() == IDOK)
		{
			if (OnCheckFile(filedlg.m_szFileName))
			{
				SetDlgItemText(IDC_EDIT1, filedlg.m_szFileName);

				PathRemoveExtension(filedlg.m_szFileName);
				wcscat_s(filedlg.m_szFileName, L".cpp");
				SetDlgItemText(IDC_EDIT2, filedlg.m_szFileName);
			}
		}

		return 0;
	}

	LRESULT OnBrowserFile2(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CFileDialog		filedlg(FALSE,
								NULL,
								NULL,
								NULL,
								L"Source File(*.cpp)\0*.cpp\0\0",
								this->m_hWnd);

		if (filedlg.DoModal() == IDOK)
		{
			SetDlgItemText(IDC_EDIT2, filedlg.m_szFileName);
		}
		return 0;
	}

	LRESULT OnDropFile(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		UINT nCount;
		WCHAR szPath[MAX_PATH];
		HDROP	hDropInfo = (HDROP)wParam;

		nCount = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);
		if (nCount)
		{
			for (UINT nIndex = 0; nIndex < nCount; ++nIndex)
			{
				DragQueryFile(hDropInfo, nIndex, szPath, _countof(szPath));

				if (OnCheckFile(szPath))
				{
					SetDlgItemText(IDC_EDIT1, szPath);

					PathRemoveExtension(szPath);
					wcscat_s(szPath, L".cpp");
					SetDlgItemText(IDC_EDIT2, szPath);
				}

				break;
			}
		}

		DragFinish(hDropInfo);

		return 0;
	}

	LRESULT OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// unregister message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->RemoveMessageFilter(this);
		pLoop->RemoveIdleHandler(this);
		return 0;
	}

	LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		CloseDialog(0);
		return 0;
	}

	LRESULT OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CAboutDlg dlg;
		dlg.DoModal();
		return 0;
	}

	LRESULT OnExit(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		// TODO: Add validation code 
		CloseDialog(wID);
		ExitProcess(0);
		return 0;
	}

	void CloseDialog(int nVal)
	{
		DestroyWindow();
		::PostQuitMessage(nVal);
	}
};
