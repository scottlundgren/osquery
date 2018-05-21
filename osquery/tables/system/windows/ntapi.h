/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 *
 *  The purpose of this header is to provide a common place to define Windows
 *  native api constructs for use across Windows-specific tables
 *
*/

#pragma once

#include <windows.h>
#include <osquery/core.h>
#include <osquery/tables.h>
namespace osquery {
namespace tables {

#define NTSTATUS				ULONG
#define STATUS_SUCCESS          0L
#define OBJ_CASE_INSENSITIVE    64L
#define DIRECTORY_QUERY         0x0001
#define SYMBOLIC_LINK_QUERY     0x0001

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    PVOID           RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *ZwQueryObject)(HANDLE h, INT /*OBJECT_INFORMATION_CLASS*/ oic, PVOID ObjectInformation,
    ULONG ObjectInformationLength, PULONG ReturnLength);

typedef NTSTATUS(WINAPI *ZwQuerySystemInformation)(INT /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
    PVOID SystemInformation, IN ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(WINAPI *NTCLOSE)(
    _In_ HANDLE Handle
    );

typedef NTSTATUS(WINAPI *NTOPENDIRECTORYOBJECT)(
    _Out_  PHANDLE DirectoryHandle,
    _In_   ACCESS_MASK DesiredAccess,
    _In_   POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(WINAPI *NTQUERYDIRECTORYOBJECT)(
    _In_       HANDLE DirectoryHandle,
    _Out_opt_  PVOID Buffer,
    _In_       ULONG Length,
    _In_       BOOLEAN ReturnSingleEntry,
    _In_       BOOLEAN RestartScan,
    _Inout_    PULONG Context,
    _Out_opt_  PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI *NTOPENSYMBOLICLINKOBJECT)(
    _Out_  PHANDLE LinkHandle,
    _In_   ACCESS_MASK DesiredAccess,
    _In_   POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(WINAPI *NTQUERYSYMBOLICLINKOBJECT)(
    _In_       HANDLE LinkHandle,
    _Inout_    PUNICODE_STRING LinkTarget,
    _Out_opt_  PULONG ReturnedLength
    );

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG		ProcessId;
    BYTE		ObjectTypeNumber;
    BYTE		Flags;
    USHORT		Handle;
    PVOID		Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJDIR_INFORMATION {
    UNICODE_STRING          ObjectName;
    UNICODE_STRING          ObjectTypeName;
    BYTE                    Data[1];
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

} // namespace tables
} // namespace osquery
