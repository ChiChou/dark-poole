---
layout:	post
title:	"Bypass macOS Rootless by Sandboxing"
date:	2018-06-18
image: /img/2018-06-18-bypass-macos-rootless-by-sandboxing/elevated.png
show_excerpt: true
---

This bug has been fixed in Mojave Beta, but still present in latest High Sierra (10.13.5). It's a logic bug that an entitled binary tries to load an insecure external library controllable by environment variable. To exploit it we need to abuse sandbox, which is interesting that sometimes a mitigation could be turned to an exploit.

CoreSymbolication(`/System/Library/PrivateFrameworks/CoreSymbolication.framework`) has some private api for symbolication. When demangling swift application symbols, it tries to load external library in following order:

* `/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib`
* `/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib`
* `/usr/lib/libswiftDemangle.dylib`
* `${xcselect_get_developer_dir_path()}/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib`

<!-- more -->

```c
handle = _dlopen("/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib", 1);

if (!handle && ((len = get_path_relative_to_framework_contents("../../Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/", "libswiftDemangle.dylib", alternative_path, 0x400), len == 0 || (handle = _dlopen(alternative_path, 1), handle == 0)))) && ((len2 = get_path_relative_to_framework_contents("../../usr/lib/libswiftDemangle.dylib", alternative_path, 0x400), len2 == 0 || (handle = _dlopen(alternative_path, 1), handle == 0)))) {
  handle_xcselect = _dlopen("/usr/lib/libxcselect.dylib", 1);
  if (handle_xcselect == 0)
    goto cleanup;

  p_get_dev_dir_path = (undefined *)_dlsym(handle_xcselect, "xcselect_get_developer_dir_path");

  if ((p_get_dev_dir_path == (undefined *)0x0) || (cVar2 = (*(code *)p_get_dev_dir_path)(alternative_path, 0x400, &local_42b, &local_42a, &local_429), cVar2 == 0)) {
    handle = 0;
  } else {
    _strlcat(alternative_path, "/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib", 0x400);
    handle = _dlopen(alternative_path, 1);
  }

  _dlclose(handle_xcselect);

  if (handle == 0)
    goto cleanup;
}

__ZL25demanglerLibraryFunctions.0 = _dlsym(handle, "swift_demangle_getSimplifiedDemangledName");​

```

The function `xcselect_get_developer_dir_path` will return environ variable `DEVELOPER_DIR` if it's set. Absolutely controllable.

Actually the first `libswiftDemangle.dylib` candidate does exist. Will it reach the vulnerable branch? I'll talk about it later.

Apple has built-in `com.apple.SamplingTools` in:

```
/usr/bin/{filtercalltree,heap32,stringdups32,leaks32,heap,atos,vmmap32,sample,malloc_history32,symbols,vmmap,leaks,stringdups,malloc_history}
```

And they are entitled:

```shell
➜ ~ jtool --ent `which symbols`
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "<http://www.apple.com/DTDs/PropertyList-1.0.dtd>">
<plist version="1.0">
<dict>
 <key>com.apple.private.kernel.get-kext-info</key>
 <true/>
 <key>com.apple.system-task-ports</key>
 <true/>
</dict>
</plist>
```

With this entitlement, SamplingTools can attach to SIP protected process with `task_for_pid`, even without root privilege.

```
$ vmmap Finder | head -n 8
Process: Finder [42164]
Path: /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
Load Address: 0x10515f000
Identifier: com.apple.finder
Version: 10.13.5 (10.13.5)
Build Info: Finder_FE-1054005004000000~3
Code Type: X86-64
Parent Process: ??? [1]
```

LLDB fails even it's root:

```
$ sudo lldb -n Finder
Password:
(lldb) process attach --name "Finder"
error: attach failed: cannot attach to process due to System Integrity Protection
```

So this seems to be like a meta entitlement. With it you can just inject to other entitled process and gain arbitrary entitlement.

Let's just start an application compiled with swift, then run `symbols [pid] -printDemangling` and it will call CoreSymbolication!demangle, which has potential ability to load insecure code.

But there are two problems. First, the last branch looks impossible to be reached because `/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib` exists.

Actually we can just block them with a sandbox. **Yeah, use the security facility to trigger something insecure.**

```lisp
(version 1)
(allow default)
(deny file-read*
  (literal "/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib")
  (literal "/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib")
  (literal "/usr/lib/libswiftDemangle.dylib")
)
```

Then, spawn a child process with `symbols [pid] -printDemangling` to trigger dylib hijack.

Now we have a second problem. It crashes.

```
System Integrity Protection: enabled
Crashed Thread: 0 Dispatch queue: com.apple.main-threadException Type: EXC_BAD_ACCESS (Code Signature Invalid)
Exception Codes: 0x0000000000000032, 0x000000010d745000
Exception Note: EXC_CORPSE_NOTIFY
Termination Reason: Namespace CODESIGNING, Code 0x2
kernel messages:
External Modification Warnings:
Process used task_for_pid().
VM Regions Near 0x10d745000:
 MALLOC_LARGE 000000010d70a000-000000010d745000 [ 236K] rw-/rwx SM=PRV
--> mapped file 000000010d745000-000000010d746000 [ 4K] r-x/r-x SM=PRV Object_id=2929ab85
 mapped file 000000010d748000-000000010d762000 [ 104K] r--/r-- SM=ALI Object_id=2af85085Application Specific Information:
dyld: in dlopen()
/var/folders/4d/1_vz_55x0mn_w1cyjwr9w42c0000gn/T/tmp.0b5SeUjh/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib
12 libdyld.dylib 0x00007fff66c9fd86 dlopen + 86
13 com.apple.CoreSymbolication 0x00007fff52d15332 invocation function for block in call_external_demangle(char const*) + 348
14 libdispatch.dylib 0x00007fff66c64e08 _dispatch_client_callout + 8
15 libdispatch.dylib 0x00007fff66c64dbb dispatch_once_f + 41
16 com.apple.CoreSymbolication 0x00007fff52cb880f demangle + 298
17 com.apple.CoreSymbolication 0x00007fff52cb85e3 TRawSymbol<Pointer64>::name() + 75
18 com.apple.CoreSymbolication 0x00007fff52cbd88e CSSymbolGetName + 166
```

com.apple.SamplingTools in latest macOS are code signed with [Library Validation](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) flag, so loading unsigned dylib is prohibited.

```
➜ ~ codesign -dvvv `which symbols`
Executable=/usr/bin/symbols
Identifier=com.apple.SamplingTools
Format=Mach-O thin (x86_64)
CodeDirectory v=20100 size=1384 flags=**0x2000(library-validation) **hashes=36+5 location=embedded
```

I just happened to have an El Capitan virtual machine and I looked into it. The previous SamplingTools distribution has valid code signature, but no library validation flag. So just copy to High Sierra and it works.

Although we can now invoke `task_for_pid` on any restricted process, it still requires the same euid, which means we need a local root privilege escalation exploit as part of the chain.

Now inject into `diskmanagementd` and you'll have the `com.apple.rootless.install.heritable` entitlement, which means the privilege to modify `/System` and spawn a shell without rootless restriction.

The bug has been fixed in Mojave Beta, no more external library, finally.

```objc
void ____ZL22call_external_demanglePKc_block_invoke(void) {
  char *bDoNotDemangleSwift;
  void *handle;

  bDoNotDemangleSwift = _getenv("CS_DO_NOT_DEMANGLE_SWIFT");
  if ((bDoNotDemangleSwift == NULL) ||
     (((byte)(*bDoNotDemangleSwift - 0x30U) < 0x3f &&
      ((0x4000000040000001U >> ((ulong)(byte)(*bDoNotDemangleSwift - 0x30U) & 0x1f) & 1) != 0)))) {

    handle = _dlopen("/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib",1);
    if (handle != 0) {
      __ZL25demanglerLibraryFunctions.0 = _dlsym(handle,"swift_demangle_getSimplifiedDemangledName");
    }
  }
  return;
}
```

#### Update 2019-05-14

This bug be exploited for kernel privilege escalation. Please refer to the slides for my HITB Ams 2019 talk:

<https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20ModJack%20-%20Hijacking%20the%20MacOS%20Kernel%20-%20Zhi%20Zhou.pdf>

It's not XNU who validates code signature for kernel extensions, but those userspace executables that own the entitlement `com.apple.rootless.kext-secure-management` entitlement. These binaries are `kextd`, `kextutil` and `kextload` on 10.13.x. 

Once you own the entitlement, you rule the kernel. The process can invoke `kext_request` to kindly ask XNU to load an extension:

```c
kern_return_t kext_request(
  host_priv_t host_priv,
  uint32_t user_log_flags,
  vm_offset_t request_data,
  mach_msg_type_number_t request_dataCnt,
  vm_offset_t *response_data,
  mach_msg_type_number_t *response_dataCnt,
  vm_offset_t *log_data,
  mach_msg_type_number_t *log_dataCnt,
  kern_return_t *op_result);
```

Parameter `request_data` is an MKEXT message, serialized in XML format, while `response_data` is for reading the response back and `log_data` gives the logs.

This is an example of MKEXT request:

<p class="full"><img src="/img/2018-06-18-bypass-macos-rootless-by-sandboxing/mkext.svg" alt="MKEXT"></p>

It consists of three parts:

* header
* file entry
* plist

<p class="full"><img src="/img/2018-06-18-bypass-macos-rootless-by-sandboxing/mkext2-structure.svg" alt="mkext2 structure"></p>

The header defines basic information like packet length, checksum, version and CPU type. File entry has the full binary of the kernel extension. A single MKEXT request can have multiple file entries.

```c
typedef struct mkext2_file_entry {
  uint32_t  compressed_size;  // if zero, file is not compressed
  uint32_t  full_size;        // full size of data w/o this struct
  uint8_t   data[0];          // data is inline to this struct
} mkext2_file_entry;
```

At the end of the packet is the plist metadata. It has the identifier, dependencies, path and part of the `Info.plist` of the kext bundle.

Since it's the userspace that does the validation, my exploit simply patches the kill-switch of process `kextd` to allow arbitrary unsigned kext to be loaded.

The service `kextd` checks the following conditions when we run `kextload`:

* Signed: `OSKextIsAuthentic`
* To avoid malicious modification during kext loading, it has a special staging process that the extension must be moved to a SIP-protected location. This process is ensured by function `rootless_check_trusted_class`
* Finally, `kextd` will ask user's approval by invoking this method `-[SPKernelExtensionPolicy canLoadKernelExtensionInCache:error]`

All of the functions have a same shortcut that, when `csr_check` (the syscall that checks the state of SIP) returns false, it will load arbitrary kext and ignore all the requirements. By reusing `kextool`, we don't have to manually serialize a valid `kext_request` on our own. 

Here's the exploit to load an unsigned kernel extension on macOS 10.13:

[**ChiChou/sploits**](https://github.com/ChiChou/sploits/tree/master/ModJack)
