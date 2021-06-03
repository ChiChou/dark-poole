---
layout:	post
title:	"Rootpipe Reborn (Part II): CVE-2019-8565 Feedback Assistant Race Condition"
date:	2019-04-21
show_excerpt: true
---

## Background

There's a general bug type on macOS. When a privileged (or loosely sandboxed) user space process accepts an IPC message from an unprivileged or sandboxed client, it decides whether the operation is valid by enforcing code signature (bundle id, authority or [entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AboutEntitlements.html)). If such security check is based on process id, it can be bypassed via pid reuse attack.

<!-- more -->

An unprivileged client can send an IPC message, then spawns an entitled process to reuse current pid. The privileged service will then validate on the new process and accept the previous IPC request, leading to privilege escalation or even sandbox escape. The attacker can stably win the race by spawning multiple child processes to fill up the message queue.

Security checks based on pid, like `sandbox_check` and `SecTaskCreateWithPID` suffer from this attack.

The idea and the initial PoC was borrowed from Ian Beer:

* [Issue 1223: MacOS/iOS userspace entitlement checking is racy](https://bugs.chromium.org/p/project-zero/issues/detail?id=1223)

Samuel Groß has also been aware of this senario:

* [Don't Trust the PID! Stories of a simple logic bug and where to find it](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
* [Pwn2Own: Safari sandbox part 2 — Wrap your way around to root](https://phoenhex.re/2017-07-06/pwn2own-sandbox-escape#performing-the-right-check-on-the-wrong-process)

Put another way, the IPC server should never use `xpc_connection_get_pid` or `[NSXPCConnection processIdentifier]` to check the validity of incoming clients. It should use the `audit_token_t` instead (note: there was an exception).

Unfortunately these functions are undocumented and private:

* `xpc_connection_get_audit_token`
* `[NSXPCConnection auditToken]`

Since, as noted, these methods are private, third-party developers are trapped in this issue repeatedly:

* <https://hackerone.com/reports/470003>
* <https://github.com/google/macops-MOLXPCConnection/issues/3>

Apple please consider opening these functions to developers!

Oh wait. Actually `audit_token_t` was not so trustworthy. [@5aelo](https://twitter.com/5aelo) has just pointed out another bug before iOS 12.2 / macOS 10.14.4: [Issue 1757: XNU: pidversion increment during execve is unsafe](https://bugs.chromium.org/p/project-zero/issues/detail?id=1757) 🤦‍♂

## The bug

The privileged XPC service com.apple.appleseed.fbahelperd has exported the following interface:

```objectivec
@protocol FBAPrivilegedDaemon <NSObject>
- (void)copyLogFiles:(NSDictionary *)arg1;
- (void)gatherInstallLogsWithDestination:(NSURL *)arg1;
- (void)gatherSyslogsWithDestination:(NSURL *)arg1;
- (void)sampleProcessWithPID:(unsigned long long)arg1 withDestination:(NSURL *)arg2;
- (void)runMDSDiagnoseWithDestination:(NSURL *)arg1;
- (void)runTMDiagnoseWithDestination:(NSURL *)arg1;
- (void)runBluetoothDiagnoseWithDestination:(NSURL *)arg1 shortUserName:(NSString *)arg2;
- (void)runWifiDiagnoseWithDestination:(NSURL *)arg1;
- (void)runSysdiagnoseWithDestination:(NSURL *)arg1 arguments:(NSArray *)arg2;
- (void)runSysdiagnoseWithDestination:(NSURL *)arg1;
- (void)runMobilityReportWithDestination:(NSURL *)arg1;
- (void)runSystemProfileWithDetailLevel:(NSString *)arg1 destination:(NSURL *)arg2;
- (void)stopDaemon;
- (void)showPrivileges;
- (void)performReadyCheck;
@end
```

Look at the implementation of `-[FBAPrivilegedDaemon listener:shouldAcceptNewConnection:]` method. It only allows XPC messages from one client: `/System/Library/CoreServices/Applications/Feedback Assistant.app/Contents/MacOS/Feedback Assistant`

![](/img/s3GRWFBhnSAnfvNA2D_d7A.png)
![](/img/UAEP_VYOATMGYqgRr_A5gQ.png)

But since it performs the security check based on process id, we can bypass it. You can now refer to the proof of concept by Ian Beer (<https://bugs.chromium.org/p/project-zero/issues/attachmentText?aid=276656>) or see my full exploit at the end.

The steps to trigger the race condition are as follows:

1. Create multiple client processes via `posix_spawn` or `NSTask` (note: you can't do this on iOS)
2. Better not to use fork because Objective-C runtime may crash if you call it between fork and exec, which is required by this attack. On 10.13 you can add a OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES environment variable before process creation or add a `__DATA,__objc_fork_ok` section to your executable as a workaround. But these workarounds are not compatible with previous macOS. For more information, please refer to <http://www.sealiesoftware.com/blog/archive/2017/6/5/Objective-C_and_fork_in_macOS_1013.html>
3. Send multiple XPC messages to the server to block the message queue
4. Ian Beer uses `execve` to replace the binary to a trusted one and write to its its buffer to prevent the new process from terminating. Instead, I chose to pass these flags `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` to `posix_spawn` to create a suspended child process and reuse the pid of the parent
5. Since the child process has been replaced, there won't be any callback. You have to use a "canary" to detect whether the race is successful based on the server's behavior, e.g., the existence of a newly created file

From the console output, the server accepts our request:

![](/img/upl0TAIffe77rXYMsCIJwg.png)

Now the check is passed

## Give Me Root

Now continue code auditing on `FBAPrivilegedDaemon`.

The method `copyLogFiles:` accepts one `NSDictionary` argument, whose keys as the sources and the correspond `NSString` as destination to perform file copy. It supports multiple tasks at once, and the path can be both directory or file.

`-[FBAPrivilegedDaemon copyLogFiles:]`

```objectivec
if ([src hasPrefix:@"/LibraryLogs"] || [src hasPrefix:@"/var/log"]) {
  if (![self canModifyPath:dst]) {
    result[src] = [NSString stringWithFormat:@"Invalid destination: %@", dst];
  } else {
    result[src] = @"File must be copied from a log directory";
  }
}
```

`-[FBAPrivilegedDaemon canModifyPath:]`

```objectivec
if ([dst hasPrefix:@"/var/folders/"] || [dst hasPrefix:@"/private/var/"] || [dst hasPrefix:@"/tmp/"]) {
  return TRUE;
} else {
  return [dst rangeOfString:@"Library/Caches/com.apple.appleseed.FeedbackAssistant"] != 0;
}
```

The source must start with `/Library/Logs` or` /var/log`, and the destination must match one the following patterns:

* ^\/var\/folders
* ^\/private\/var\/
* ^\/tmp
* Library\/Caches\/com\.apple\.appleseed\.FeedbackAssistant

It will not override an existing destination.

These constraints can be bypassed throuth path traversal. So now we can copy arbitrary file or folder to anywhere unless rootless protected.

```objectivec
NSMutableDictionary *traversal(NSDictionary *mapping) {
  NSMutableDictionary *transformed = [[NSMutableDictionary alloc] init];
  for (NSString *key in mapping) {
    NSString *val = mapping[key];
    NSString *newKey = [@"/var/log/../../.." stringByAppendingPathComponent:key];
    NSString *newVal = [@"/tmp/../.." stringByAppendingPathComponent:val];
    transformed[newKey] = newVal;
  }
  return transformed;
}
```

Additionally, after each copy, it will call `-[FBAPrivilegedDaemon fixPermissionsOfURL:recursively:]` to set the copied files' owner to the XPC client process's gid and uid. This is extremely ideal for macOS LPE CTF challenges. I used this zero day exploit during #35C3 CTF to simply copy the flag and read it, lol.

If you don't mind reboot, getting root privilege is simple. Copy the executable to the places that will be automatically launched with privilege during startup. For example, the bundles in `/Library/DirectoryServices/PlugIns` will be loaded by the process `/usr/libexec/dspluginhelperd`, who has root privilege and is not sandboxed.

Can we have an instant trigger solution?

Since it will never override existing file, we can not:

* override administrator account's password digest (`/var/db/dslocal/nodes/Default/users`) ❌
* override suid binaries (not to mention file permission and rootless) ❌
* override one of the PrivilegedHelpers ❌

And it will fix file permissions, none of these would work:

* add sudoer ❌
* add an entry to /Library/LaunchDaemons to register a new XPC service ❌

We need more primitives.

The daemon has other methods named `run*diagnoseWithDestination`. They are various external command wrappers just like those diagnose helpers mentioned from my previous post. What's interesting is that runTMDiagnoseWithDestination: acts the same as timemachinehelper , thus we can trigger the CVE-2019-8513 command injection.

At first I was looking at runMDSDiagnoseWithDestination: , who launches /usr/bin/mddiagnose that will finally spawn /usr/local/bin/ddt after around 10 seconds, waiting for the /usr/bin/top command to end. Remember the previous post? This location does not exist by default and we can put custom executable with the arbitrary file copy bug.

![](/img/t-r6124cbq4Ac4Q5CHnhNQ.png)

Another exploit path is method `runMobilityReportWithDestination:`. It invokes this shell script: `/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Resources/get-mobility-info`

The script checks the existence of `/usr/local/bin/netdiagnose`. If so, execute it as root. The exploit will success within milliseconds.

![](/img/O2buvbSU9gtM0VkB5b67FA.png)

By the way, I was surprised by how many diagnostic tools depending on the non-existing directory `/usr/local/bin`.

![](/img/d8BjICtE2TB-xuZLe98sXQ.png)

The bug has been fixed in macOS 10.14.4 and iOS 12.2.

* [About the security content of iOS 12.2](https://support.apple.com/en-us/HT209599)
* [About the security content of macOS Mojave 10.14.4, Security Update 2019-002 High Sierra, Security...](https://support.apple.com/en-in/HT209600)

## PoC

<https://github.com/ChiChou/sploits/tree/master/CVE-2019-8565>

