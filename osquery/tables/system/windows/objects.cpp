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

#include "ntapi.h"
#include "kobjhandle.h"


#include <Windows.h>
#include <strsafe.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/core/windows/wmi.h>


namespace osquery {
namespace tables {

// enumerate all objects in the Windows object namespace
// does not provide support for recursion
//
// example at:
//    http://pastebin.com/embed_js/zhmJTffK
//    https://randomsourcecode.wordpress.com/2015/03/14/enumerating-deviceobjects-from-user-mode/
//    https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
//
std::vector<std::pair<std::wstring, std::wstring>> EnumerateObjectNamespace(std::wstring strRoot) {

  std::vector<std::pair<std::wstring, std::wstring>> thingies;

  // look up addresses of NtQueryDirectoryObject and
  // NtQuerySymbolicLinkObject.  Both are exported from ntdll
  //
  // NtQueryDirectoryObject is documented on MSDN, there is no
  // associated header or import library
  NTQUERYDIRECTORYOBJECT NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtQueryDirectoryObject");
  if (NULL == NtQueryDirectoryObject) {
      return thingies;
  }

  // open the caller-provided root directory
  KObjHandle kdo;
  if (!kdo.openDirObj(strRoot)) {
    return thingies;
  }
	
  // iterator index is incremented by NtQueryDirectoryObject
  for (DWORD index = 0;;) {
    BYTE rgDirObjInfoBuffer[1024 * 8] = { 0 };
    POBJDIR_INFORMATION pObjDirInfo = (POBJDIR_INFORMATION)rgDirObjInfoBuffer;
    memset(rgDirObjInfoBuffer, 0, sizeof(rgDirObjInfoBuffer));

    NTSTATUS ntStatus = NtQueryDirectoryObject(kdo.getAsHandle(),
                                      pObjDirInfo,
                                      sizeof(rgDirObjInfoBuffer),
                                      TRUE,
                                      FALSE,
                                      &index,
                                      NULL);
    if (STATUS_SUCCESS != ntStatus) {
      // todo: error check here
      break;
    }

    std::pair<std::wstring, std::wstring> x;
    x.first = (pObjDirInfo->ObjectName.Buffer);
    x.second = (pObjDirInfo->ObjectTypeName.Buffer);

    thingies.push_back(x);
  }

  return thingies;
}

// callback function to be invoked for each object discovered in
// the windows object directory "\Sessions\BNOLINKS"
//
// for each enumerated object, verify some assumptions and then
// enumerate the object directory referenced by the object
//
BOOL CALLBACK EnumerateBaseNamedObjectsLinks(POBJDIR_INFORMATION pObjDirInfo,
                                             PVOID p) {
  NTSTATUS ntStatus;
  NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject = NULL;
  WCHAR wzSessionPath[MAX_PATH], wzSymbolicLinkTarget[MAX_PATH] = {L'\0'};
  HANDLE hSymbolicLink = NULL;
  UNICODE_STRING usSymbolicLinkTarget;

  // look up NtQuerySymbolicLinkObject as exported from ntdll
  NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(
      GetModuleHandleA("ntdll"), "NtQuerySymbolicLinkObject");
  if (NULL == NtQuerySymbolicLinkObject) {
      return FALSE;
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
  if (0 != wcscmp(L"SymbolicLink", pObjDirInfo->ObjectTypeName.Buffer)) {
    return FALSE;
  }

  // validate that this appears to be a valid terminal services session id
  // another approach is to enumerate windows terminal services sessions with
  // WTSEnumerateSessions
  // and validate against that list
  //
  if (!(0 == wcscmp(L"0", pObjDirInfo->ObjectName.Buffer) ||
        _wtoi(pObjDirInfo->ObjectName.Buffer) > 0)) {
    return FALSE;
  }

  // at this point we have SymbolicLink with a name matching a terminal services
  // session id
  // build the fully qualified object path
  HRESULT hr = StringCchPrintfW(wzSessionPath,
                        MAX_PATH,
                        L"%s\\%s",
                        L"\\Sessions\\BNOLINKS",
                        pObjDirInfo->ObjectName.Buffer);
  if (FAILED(hr)) {
    return FALSE;
  }

  // open the symbolic link itself in order to determine the target of the link
  KObjHandle slo;
  if (!slo.openSymLinkObj(wzSessionPath)) {
    LOG(INFO) << "OpenSymbolicLink failed with 0x" << std::hex << hr << " for "
      << wzSessionPath;
    return FALSE;
  }

  usSymbolicLinkTarget.Buffer = wzSymbolicLinkTarget;
  usSymbolicLinkTarget.Length = 0;
  usSymbolicLinkTarget.MaximumLength = sizeof(wzSymbolicLinkTarget);

  ntStatus =
      NtQuerySymbolicLinkObject(hSymbolicLink, &usSymbolicLinkTarget, NULL);
  if (STATUS_SUCCESS != ntStatus) {
    return FALSE;
  }

  std::vector<std::pair<std::wstring, std::wstring>> thingies = EnumerateObjectNamespace(usSymbolicLinkTarget.Buffer);

  

  return TRUE;
}


QueryData genBaseNamedObjects(QueryContext& context) {
  QueryData results;

  // enumerate the base named objects in each terminal services session
  std::vector<std::pair<std::wstring, std::wstring>> sessions = EnumerateObjectNamespace(L"\\Sessions\\BNOLINKS");
 
  for (auto & element : sessions) {
    Row r;
    r["object_name"] = wstringToString(element.first.c_str());
    r["object_type"] = wstringToString(element.second.c_str());

    results.push_back(r);

  }

  return results;
}
}
}
