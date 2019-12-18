#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdexcept>
#include <memory>
#include <string>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

struct Account {
	std::wstring name;
	std::wstring domain;
	SID_NAME_USE use;
};

Account GetAccount(PSID sid) {
	wchar_t name[128], domain[128];
	DWORD szName = sizeof name / sizeof name[0];
	DWORD szDomain = sizeof domain / sizeof name[0];
	SID_NAME_USE use;
	if (!LookupAccountSid(NULL, sid, name, &szName, domain, &szDomain, &use)) {
		printf("LookupAccountSid failed(%d)\n", GetLastError());
		throw std::runtime_error("LookupAccountSid failed");
	}
	Account account;
	account.name.assign(name);
	account.domain.assign(domain);
	account.use = use;
	return account;
}

class SecurityDescriptor {
	std::unique_ptr<SECURITY_DESCRIPTOR> psd;
	friend class Service;
	SecurityDescriptor(SC_HANDLE handle, SECURITY_INFORMATION si) {
		psd.reset(new SECURITY_DESCRIPTOR);
		DWORD                dwSize = 0;
		DWORD				 dwBytesNeeded = 0;
		// Get the current security descriptor.
		if (!QueryServiceObjectSecurity(handle,
			si,
			psd.get(),
			sizeof * psd.get(),
			&dwBytesNeeded))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				dwSize = dwBytesNeeded;
				psd.reset(reinterpret_cast<SECURITY_DESCRIPTOR*>(new uint8_t[dwSize]));
				if (!QueryServiceObjectSecurity(handle,
					si, psd.get(), dwSize, &dwBytesNeeded))
				{
					printf("QueryServiceObjectSecurity second failed (%d)\n", GetLastError());
					throw std::runtime_error("QueryServiceObjectSecurity failed");
				}
			}
			else
			{
				printf("QueryServiceObjectSecurity failed (%d)\n", GetLastError());
				throw std::runtime_error("QueryServiceObjectSecurity failed");
			}
		}
	}
public:
	void Print() {
		PACL                 pacl = NULL;
		PACL                 pNewAcl = NULL;
		PSID                 pOwner = NULL;
		BOOL                 bOwnerDefaulted = FALSE;
		PSID                 pGroup = NULL;
		BOOL                 bGroupDefaulted = FALSE;
		BOOL                 bDaclPresent = FALSE;
		BOOL                 bDaclDefaulted = FALSE;
		// Get owner
		if (!GetSecurityDescriptorOwner(psd.get(), &pOwner, &bOwnerDefaulted)) {
			printf("GetSecurityDescriptorOwner failed(%d)\n", GetLastError());
			throw std::runtime_error("GetSecurityDescriptorOwner failed");
		}
		auto owner = GetAccount(pOwner);
		wprintf(L"owner: %s/%s %d %d\n", owner.name.c_str(), owner.domain.c_str(), owner.use, bOwnerDefaulted);

		// Get group
		if (!GetSecurityDescriptorGroup(psd.get(), &pGroup, &bGroupDefaulted)) {
			printf("GetSecurityDescriptorGroup failed(%d)\n", GetLastError());
			throw std::runtime_error("GetSecurityDescriptorGroup failed");
		}
		auto group = GetAccount(pGroup);
		wprintf(L"group: %s/%s %d %d\n", group.name.c_str(), group.domain.c_str(), group.use, bGroupDefaulted);

		// Get the DACL.
		if (!GetSecurityDescriptorDacl(psd.get(), &bDaclPresent, &pacl,
			&bDaclDefaulted))
		{
			printf("GetSecurityDescriptorDacl failed(%d)\n", GetLastError());
			throw std::runtime_error("GetSecurityDescriptorDacl failed");
		}

		if (bDaclPresent) {
			printf("dacl count: %d\n", pacl->AceCount);
			ULONG count;
			PEXPLICIT_ACCESS plist;
			auto ret = GetExplicitEntriesFromAcl(pacl, &count, &plist);
			if (ret != ERROR_SUCCESS) {
				printf("GetExplicitEntriesFromAcl failed:%d\n", ret);
				return;
			}
			printf("got %u\n", count);
			for (ULONG i = 0; i < count; i++) {
				printf("%d %x %d %d %d ", plist[i].grfAccessMode, plist[i].grfAccessPermissions, plist[i].grfInheritance,
					plist[i].Trustee.TrusteeForm, plist[i].Trustee.TrusteeType);
				switch (plist[i].Trustee.TrusteeType) {
				case TRUSTEE_IS_SID:
				{
					SID* sid = reinterpret_cast<SID*>(plist[i].Trustee.ptstrName);
					auto account = GetAccount(sid);
					wprintf(L" %s/%s:%d ", account.domain.c_str(), account.name.c_str(), account.use);
					/*if (lstrcmpi(domain, L"NT AUTHORITY") == 0 && (
						lstrcmpi(name, L"Authenticated Users") == 0 ||
						lstrcmpi(name, L"SYSTEM") == 0
						)) {
						plist[i].grfAccessPermissions = SERVICE_ALL_ACCESS;
						SetEntriesInAcl(count, plist, NULL, &pNewAcl);
					}*/
					break;
				}
				default:
					printf(" unknown trustee_from ");
				}
				printf("\n");
			}

			//if (pNewAcl != NULL) {
			//	SECURITY_DESCRIPTOR  sd;
			//	if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
			//		printf("InitializeSecurityDescriptor failed(%d)\n", GetLastError());
			//		throw std::runtime_error("InitializeSecurityDescriptor failed");
			//	}
			//	if (!SetSecurityDescriptorDacl(&sd, TRUE, pNewAcl, FALSE)) {
			//		printf("SetSecurityDescriptorDacl failed(%d)\n", GetLastError());
			//		throw std::runtime_error("SetSecurityDescriptorDacl failed");
			//	}
			//	if (!SetServiceObjectSecurity(handle,
			//		DACL_SECURITY_INFORMATION, &sd))
			//	{
			//		printf("SetServiceObjectSecurity failed(%d)\n", GetLastError());
			//		throw std::runtime_error("SetServiceObjectSecurity failed");
			//	}
			//	else printf("Service DACL updated successfully\n");
			//}
		}
		else {
			printf("no dacl present\n");
		}
	}
	PACL Takeown() {
		PACL                 pacl = NULL;
		PACL                 pNewAcl = NULL;
		BOOL                 bDaclPresent = FALSE;
		BOOL                 bDaclDefaulted = FALSE;
		// Get the DACL.
		if (!GetSecurityDescriptorDacl(psd.get(), &bDaclPresent, &pacl,
			&bDaclDefaulted))
		{
			printf("GetSecurityDescriptorDacl failed(%d)\n", GetLastError());
			throw std::runtime_error("GetSecurityDescriptorDacl failed");
		}

		if (bDaclPresent) {
			printf("dacl count: %d\n", pacl->AceCount);
			ULONG count;
			PEXPLICIT_ACCESS plist;
			auto ret = GetExplicitEntriesFromAcl(pacl, &count, &plist);
			if (ret != ERROR_SUCCESS) {
				printf("GetExplicitEntriesFromAcl failed:%d\n", ret);
				throw std::runtime_error("GetExplicitEntriesFromAcl failed");
			}
			printf("got %u\n", count);
			for (ULONG i = 0; i < count; i++) {
				printf("%d %x %d %d %d ", plist[i].grfAccessMode, plist[i].grfAccessPermissions, plist[i].grfInheritance,
					plist[i].Trustee.TrusteeForm, plist[i].Trustee.TrusteeType);
				switch (plist[i].Trustee.TrusteeType) {
				case TRUSTEE_IS_SID:
				{
					SID* sid = reinterpret_cast<SID*>(plist[i].Trustee.ptstrName);
					auto account = GetAccount(sid);
					wprintf(L" %s/%s:%d ", account.domain.c_str(), account.name.c_str(), account.use);
					if (lstrcmpi(account.domain.c_str(), L"NT AUTHORITY") == 0 && (
						lstrcmpi(account.name.c_str(), L"Authenticated Users") == 0 ||
						lstrcmpi(account.name.c_str(), L"SYSTEM") == 0
						)) {
						plist[i].grfAccessPermissions = SERVICE_ALL_ACCESS;
						SetEntriesInAcl(count, plist, NULL, &pNewAcl);
					}
					break;
				}
				default:
					printf(" unknown trustee_from ");
				}
				printf("\n");
			}

			return pNewAcl;
		}
		throw std::runtime_error("no dacl present");
	}
};

class Service {
	SC_HANDLE handle;
	friend class ServiceControlManager;
	Service(SC_HANDLE scm, LPCWSTR name, DWORD access) {
		handle = OpenService(scm, name, access);
		if (handle == NULL) {
			printf("OpenService failed: (%d)\n", GetLastError());
			throw std::runtime_error("OpenService failed");
		}
	}
	~Service() {
		CloseServiceHandle(handle);
	}
	void Start() {
		if (!StartService(handle, 0, NULL)) {
			printf("StartService failed (%d)\n", GetLastError());
			throw std::runtime_error("StartService failed");
		}
	}
	SERVICE_STATUS QueryStatus() {
		SERVICE_STATUS status;
		if (!QueryServiceStatus(handle, &status)) {
			printf("QueryServiceStatus failed (%d)\n", GetLastError());
			throw std::runtime_error("QueryServiceStatus failed");
		}
		return status;
	}
	SecurityDescriptor QuerySecurity() {
		return SecurityDescriptor(handle, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
	}

	void UpdateSecurity(PACL pNewAcl) {
		SECURITY_DESCRIPTOR  sd;
		if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
			printf("InitializeSecurityDescriptor failed(%d)\n", GetLastError());
			throw std::runtime_error("InitializeSecurityDescriptor failed");
		}
		if (!SetSecurityDescriptorDacl(&sd, TRUE, pNewAcl, FALSE)) {
			printf("SetSecurityDescriptorDacl failed(%d)\n", GetLastError());
			throw std::runtime_error("SetSecurityDescriptorDacl failed");
		}
		if (!SetServiceObjectSecurity(handle,
			DACL_SECURITY_INFORMATION, &sd))
		{
			printf("SetServiceObjectSecurity failed(%d)\n", GetLastError());
			throw std::runtime_error("SetServiceObjectSecurity failed");
		}
		else printf("Service DACL updated successfully\n");
	}
public:
};
class ServiceControlManager {
	SC_HANDLE handle;
public:
	ServiceControlManager(const ServiceControlManager&) = delete;
	ServiceControlManager(ServiceControlManager&&) = delete;
	ServiceControlManager& operator =(const ServiceControlManager) = delete;
	ServiceControlManager() {
		handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL) {
			printf("OpenSCManager failed (%d)\n", GetLastError());
			throw std::runtime_error("OpenSCManager failed");
		}
	}
	~ServiceControlManager() {
		CloseServiceHandle(handle);
	}

	void Start(LPCWSTR serviceName) {
		Service service(handle, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
		auto status = service.QueryStatus();
		if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING) {
			printf("Cannot start the service because it is already running\n");
			return;
		}
		service.Start();
		for (status = service.QueryStatus(); status.dwCurrentState == SERVICE_START_PENDING; Sleep(1000));
		if (status.dwCurrentState == SERVICE_RUNNING)
		{
			printf("Service started successfully.\n");
		}
		else
		{
			printf("Service not started. \n");
			printf("  Current State: %d\n", status.dwCurrentState);
			printf("  Exit Code: %d\n", status.dwWin32ExitCode);
			printf("  Check Point: %d\n", status.dwCheckPoint);
			printf("  Wait Hint: %d\n", status.dwWaitHint);
		}
	}

	void QueryConfig(LPCWSTR serviceName) {
		Service service(handle, serviceName, READ_CONTROL);
		auto psd = service.QuerySecurity();
		psd.Print();
	}

	void UpdateConfig(LPCWSTR serviceName) {
		Service service(handle, serviceName, READ_CONTROL | WRITE_DAC);
		auto psd = service.QuerySecurity();
		auto acl = psd.Takeown();
		service.UpdateSecurity(acl);
	}
};

int wmain(int argc, wchar_t** argv)
{
	if (argc > 2) {
		wprintf(L"%s [read|takeown]\n", argv[0]);
		return 0;
	}
	try {
		ServiceControlManager scm;
		if (argc == 1 || lstrcmpi(argv[1], L"read") == 0)
			scm.QueryConfig(L"SharedAccess");
		else if (lstrcmpi(argv[1], L"takeown") == 0)
			scm.UpdateConfig(L"SharedAccess");
		else wprintf(L"bad command:%s", argv[1]);
	}
	catch (std::exception & e) {
		printf("exception: %s\n", e.what());
	}
}