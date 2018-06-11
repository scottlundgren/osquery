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

#include <osquery/core.h>
#include <osquery/core/windows/kobjhandle.h>
#include <osquery/core/windows/ntapi.h>
#include <osquery/core/windows/wmi.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

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
std::vector<std::pair<std::wstring, std::wstring>> EnumerateObjectNamespace(
    std::wstring directory) {
  std::vector<std::pair<std::wstring, std::wstring>> objects;

  // look up addresses of NtQueryDirectoryObject and
  // NtQuerySymbolicLinkObject.  Both are exported from ntdll
  //
  // NtQueryDirectoryObject is documented on MSDN, there is no
  // associated header or import library
  NTQUERYDIRECTORYOBJECT NtQueryDirectoryObject =
      (NTQUERYDIRECTORYOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                             "NtQueryDirectoryObject");
  if (NULL == NtQueryDirectoryObject) {
    return objects;
  }

  // open the caller-provided root directory
  KObjHandle kdo;
  if (!kdo.openDirObj(directory)) {
    return objects;
  }

  // iterator index is incremented by NtQueryDirectoryObject
  for (DWORD index = 0;;) {
    BYTE rgDirObjInfoBuffer[1024 * 8] = {0};
    POBJDIR_INFORMATION pObjDirInfo = (POBJDIR_INFORMATION)rgDirObjInfoBuffer;

    //  get the name and type of the index'th object in the directory
    NTSTATUS ntStatus = NtQueryDirectoryObject(kdo.getAsHandle(),
                                               pObjDirInfo,
                                               sizeof(rgDirObjInfoBuffer),
                                               TRUE,
                                               FALSE,
                                               &index,
                                               NULL);
    if (STATUS_SUCCESS != ntStatus) {
      break;
    }

    std::pair<std::wstring, std::wstring> object;
    object.first = (pObjDirInfo->ObjectName.Buffer);
    object.second = (pObjDirInfo->ObjectTypeName.Buffer);

    objects.push_back(object);
  }

  return objects;
}

// enumerate all objects in a given windows terminal services session
//
// objects are found in the windows object directory
// "\Sessions\BNOLINKS\<sessionnum>"
//
std::vector<std::pair<std::wstring, std::wstring>>
EnumerateBaseNamedObjectsLinks(std::wstring sessionNum,
                               std::wstring objectType) {
  std::vector<std::pair<std::wstring, std::wstring>> objects;

  // look up NtQuerySymbolicLinkObject as exported from ntdll
  NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject =
      (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(GetModuleHandleA("ntdll"),
                                                "NtQuerySymbolicLinkObject");
  if (NULL == NtQuerySymbolicLinkObject) {
    return objects;
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
  // validate in this order
  //

  // validate (1)
  //
  // validate that this appears to be a valid terminal services session id
  // another approach is to enumerate windows terminal services sessions with
  // WTSEnumerateSessions and validate against that list
  //
  if (!(L"0" == sessionNum || std::stoi(sessionNum) > 0)) {
    return objects;
  }

  // validate (2)
  //
  // validate that the object type is "SymbolicLink"
  //
  if (L"SymbolicLink" != objectType) {
    return objects;
  }

  // at this point we have SymbolicLink with a name matching a terminal services
  // session id.  now build the fully qualified object path
  std::wstring qualifiedpath = L"\\Sessions\\BNOLINKS\\" + sessionNum;

  // open the symbolic link itself in order to determine the target of the link
  KObjHandle slo;
  if (!slo.openSymLinkObj(qualifiedpath)) {
    return objects;
  }

  UNICODE_STRING usSymbolicLinkTarget;
  WCHAR wzTargetLinkBuffer[MAX_PATH];
  usSymbolicLinkTarget.Buffer = wzTargetLinkBuffer;
  usSymbolicLinkTarget.Length = 0;
  usSymbolicLinkTarget.MaximumLength = MAX_PATH;

  NTSTATUS ntStatus =
      NtQuerySymbolicLinkObject(slo.getAsHandle(), &usSymbolicLinkTarget, NULL);
  if (STATUS_SUCCESS != ntStatus) {
    return objects;
  }

  return EnumerateObjectNamespace(usSymbolicLinkTarget.Buffer);
}

QueryData genBaseNamedObjects(QueryContext& context) {
  QueryData results;

  // enumerate the base named objects in each terminal services session
  std::vector<std::pair<std::wstring, std::wstring>> sessions =
      EnumerateObjectNamespace(L"\\Sessions\\BNOLINKS");

  for (auto& session : sessions) {
    auto objects =
        EnumerateBaseNamedObjectsLinks(session.first, session.second);

    for (auto& object : objects) {
      Row r;
      r["session_id"] = INTEGER(std::stoi(session.first));
      r["object_name"] = wstringToString(object.first.c_str());
      r["object_type"] = wstringToString(object.second.c_str());

      results.push_back(r);
    }
  }

  return results;
}
}
}
