/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>
#include <strsafe.h>
#include "ntapi.h"

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData* g_pqd = NULL;

typedef BOOL(CALLBACK *ENUMOBJECTSCALLBACKPROC)(POBJDIR_INFORMATION pObjDirInfo, PVOID pArg);

// Open a Windows symbolic link by name
// Always open with the SYMBOLIC_LINK_QUERY access mask
//
HRESULT OpenSymbolicLink(PWCHAR pwzLinkName, PHANDLE phSymbolicLink)
{
	HRESULT                     hr = E_UNEXPECTED;
	NTSTATUS                    ntStatus;
	NTOPENSYMBOLICLINKOBJECT    NtOpenSymbolicLinkObject = NULL;
	UNICODE_STRING              usLinkName;
	OBJECT_ATTRIBUTES           oa;
	size_t                      cchName;

	// look up addresse of NtOpenSymbolicLinkObject, exported from ntdll
	NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenSymbolicLinkObject");
	if (NULL == NtOpenSymbolicLinkObject)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto ErrorExit;
	}

	hr = StringCchLengthW(pwzLinkName, MAX_PATH, &cchName);
	if (FAILED(hr))
	{
		goto ErrorExit;
	}

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = NULL;
	oa.ObjectName = &usLinkName;
	oa.ObjectName->Length = LOWORD(cchName) * sizeof(WCHAR);
	oa.ObjectName->MaximumLength = LOWORD(cchName) * sizeof(WCHAR) + sizeof(WCHAR);
	oa.ObjectName->Buffer = pwzLinkName;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	ntStatus = NtOpenSymbolicLinkObject(phSymbolicLink, SYMBOLIC_LINK_QUERY, &oa);
	if (STATUS_SUCCESS != ntStatus)
	{
		hr = HRESULT_FROM_NT(ntStatus);
		goto ErrorExit;
	}

	hr = S_OK;

ErrorExit:

	return hr;
}

// Open a Windows object directory object by name
// Always open with the DIRECTORY_QUERY access mask
//
HRESULT OpenDirectory(PWCHAR pwzName, PHANDLE phDirectory)
{
	HRESULT                 hr = E_UNEXPECTED;
	NTSTATUS                ntStatus;
	OBJECT_ATTRIBUTES       oa;
	NTOPENDIRECTORYOBJECT   NtOpenDirectoryObject = NULL;
	UNICODE_STRING          us;
	size_t                  cchName;

	// protect output parameter
	*phDirectory = NULL;

	// NtOpenDirectroyObject is documented on MSDN at https://msdn.microsoft.com/en-us/library/bb470234(v=vs.85).aspx
	// there is no associated header or import library, so it must be dynamically loaded
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenDirectoryObject");
	if (NULL == NtOpenDirectoryObject)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto ErrorExit;
	}

	hr = StringCchLengthW(pwzName, MAXSHORT, &cchName);
	if (FAILED(hr))
	{
		goto ErrorExit;
	}

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = NULL;
	oa.ObjectName = &us;
	oa.ObjectName->Length = LOWORD(cchName) * sizeof(WCHAR);
	oa.ObjectName->MaximumLength = LOWORD(cchName) * sizeof(WCHAR) + sizeof(WCHAR);
	oa.ObjectName->Buffer = pwzName;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	ntStatus = NtOpenDirectoryObject(phDirectory, DIRECTORY_QUERY, &oa);
	if (STATUS_SUCCESS != ntStatus)
	{
		hr = HRESULT_FROM_NT(ntStatus);
		goto ErrorExit;
	}

	hr = S_OK;

ErrorExit:

	return hr;
}

// enumerate all objects in the Windows object namespace
// beginning with a given a starting point
//
// does not provide support for recursion
//
// example at:
//    http://pastebin.com/embed_js/zhmJTffK
//    https://randomsourcecode.wordpress.com/2015/03/14/enumerating-deviceobjects-from-user-mode/
//    https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
//
HRESULT EnumerateObjectNamespace(PWCHAR pwzRoot, ENUMOBJECTSCALLBACKPROC fnCallback, PVOID pCallbackParam)
{
	HRESULT                     hr = E_UNEXPECTED;
	NTSTATUS                    ntStatus;
	NTQUERYDIRECTORYOBJECT      NtQueryDirectoryObject = NULL;
	BYTE                        rgDirObjInfoBuffer[1024 * 8] = { 0 };
	POBJDIR_INFORMATION         pObjDirInfo = (POBJDIR_INFORMATION)rgDirObjInfoBuffer;
	HANDLE                      hRootDir = NULL;
	DWORD                       dwIndex = 0;

	// look up addresses of NtQueryDirectoryObject and
	// NtQuerySymbolicLinkObject.  Both are exported from ntdll
	//
	// NtQueryDirectoryObject is documented on MSDN, there is no
	// associated header or import library
	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryDirectoryObject");
	if (NULL == NtQueryDirectoryObject)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto ErrorExit;
	}

	// open the caller-provided root directory
	hr = OpenDirectory(pwzRoot, &hRootDir);
	if (FAILED(hr))
	{
		goto ErrorExit;
	}

	do
	{
		memset(rgDirObjInfoBuffer, 0, sizeof(rgDirObjInfoBuffer));

		ntStatus = NtQueryDirectoryObject(hRootDir,
			pObjDirInfo,
			sizeof(rgDirObjInfoBuffer),
			TRUE,
			FALSE,
			&dwIndex,
			NULL);
		if (STATUS_SUCCESS != ntStatus)
		{
			// todo: error check here
			break;
		}

		if (!fnCallback(pObjDirInfo, pCallbackParam))
		{
			hr = S_FALSE;
			goto ErrorExit;
		}

	} while (TRUE);

ErrorExit:

	if (NULL != hRootDir)
	{
		(void)CloseHandle(hRootDir);
	}

	return hr;
}

BOOL CALLBACK BaseNamedObjectsCallbackProc(POBJDIR_INFORMATION pObjDirInfo, PVOID p)
{
	CHAR	szObjectTypeNameUtf8[1024],
			szObjectNameUtf8[1024];

	if (!WideCharToMultiByte(CP_UTF8, 0, pObjDirInfo->ObjectTypeName.Buffer, -1, szObjectTypeNameUtf8, sizeof(szObjectNameUtf8), NULL, NULL))
	{
		return TRUE;
	}

	if (!WideCharToMultiByte(CP_UTF8, 0, pObjDirInfo->ObjectName.Buffer, -1, szObjectNameUtf8, sizeof(szObjectNameUtf8), NULL, NULL))
	{
		return TRUE;
	}

	Row r;

	r["object_name"] = szObjectNameUtf8;
	r["object_type"] = szObjectTypeNameUtf8;

	PWCHAR pwzSessionId = (PWCHAR)p;
	int nSessionId = _wtoi(pwzSessionId);

	r["session_id"] = INTEGER(nSessionId);

	g_pqd->push_back(r);

	return TRUE;
}

// callback function to be invoked for each object discovered in
// the windows object directory "\Sessions\BNOLINKS"
//
// for each enumerated object, verify some assumptions and then
// enumerate the object directory referenced by the object
//
BOOL CALLBACK EnumerateBaseNamedObjectsLinks(POBJDIR_INFORMATION pObjDirInfo, PVOID p)
{
	HRESULT                     hr = E_UNEXPECTED;
	NTSTATUS                    ntStatus;
	NTQUERYSYMBOLICLINKOBJECT   NtQuerySymbolicLinkObject = NULL;
	WCHAR                       wzSessionPath[MAX_PATH],
								wzSymbolicLinkTarget[MAX_PATH] = { L'\0' };
	HANDLE                      hSymbolicLink = NULL;
	UNICODE_STRING              usSymbolicLinkTarget;

	// look up NtQuerySymbolicLinkObject as exported from ntdll
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySymbolicLinkObject");
	if (NULL == NtQuerySymbolicLinkObject)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto ErrorExit;
	}

	// by convention, we expect there to be <n> objects in \Sessions\BNOLINKS with
	// the following three characteristics:
	//
	//   (1) the object name is the string representation of of an active terminal
	//       services session id.  this means we expect the object name to be a 
	//       string representation of an integer
	//
	//   (2) the object type name be "SymbolicLink"
	//
	//   (3) the symbolic link point to a directory object
	//
	// begin by validating that the object type is "SymbolicLink"
	//
	if (0 != wcscmp(L"SymbolicLink", pObjDirInfo->ObjectTypeName.Buffer))
	{
		goto ErrorExit;
	}

	// validate that this appears to be a valid terminal services session id
	// another approach is to enumerate windows terminal services sessions with WTSEnumerateSessions
	// and validate against that list
	//
	if (!(0 == wcscmp(L"0", pObjDirInfo->ObjectName.Buffer) || _wtoi(pObjDirInfo->ObjectName.Buffer) > 0))
	{
		goto ErrorExit;
	}
	
	// at this point we have SymbolicLink with a name matching a terminal services session id
	// build the fully qualified object path
	hr = StringCchPrintfW(wzSessionPath, MAX_PATH, L"%s\\%s", L"\\Sessions\\BNOLINKS", pObjDirInfo->ObjectName.Buffer);
	if (FAILED(hr))
	{
		goto ErrorExit;
	}

	// open the symbolic link itself in order to determine the target of the link
	hr = OpenSymbolicLink(wzSessionPath, &hSymbolicLink);
	if (FAILED(hr))
	{
		LOG(INFO) << "OpenSymbolicLink failed with 0x" << std::hex << hr << " for " << wzSessionPath;
		goto ErrorExit;
	}

	usSymbolicLinkTarget.Buffer = wzSymbolicLinkTarget;
	usSymbolicLinkTarget.Length = 0;
	usSymbolicLinkTarget.MaximumLength = sizeof(wzSymbolicLinkTarget);

	ntStatus = NtQuerySymbolicLinkObject(hSymbolicLink, &usSymbolicLinkTarget, NULL);
	if (STATUS_SUCCESS != ntStatus)
	{
		hr = HRESULT_FROM_NT(ntStatus);
		goto ErrorExit;
	}

	EnumerateObjectNamespace(usSymbolicLinkTarget.Buffer, BaseNamedObjectsCallbackProc, pObjDirInfo->ObjectName.Buffer);

	hr = S_OK;

ErrorExit:

	return TRUE;
}

QueryData genBaseNamedObjects(QueryContext& context) {
  QueryData results;

  g_pqd = &results;

  // enumerate the base named objects in each terminal services session
  auto hr = EnumerateObjectNamespace(L"\\Sessions\\BNOLINKS", EnumerateBaseNamedObjectsLinks, &results);
  if (FAILED(hr))
  {
	  LOG(INFO) << "Failed to enumerate basenamedobjects 0x%0.8x" << hr;
	  return results;
  }

  return results;
}
}
}
