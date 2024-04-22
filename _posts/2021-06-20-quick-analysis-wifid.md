---
layout:	post
title:	"Quick Analysis for the SSID Format String Bug"
date:	  2021-06-20
image:  /img/2021-06-20-quick-analysis-wifid/wifi.png
desc:   A rogue Wi-Fi hotspot can crash your phone.
---

Days ago a [twitter post](https://twitter.com/vm_call/status/1405937492642123782) revealed a bug in iOS Wi-Fi service:

> After joining my personal WiFi with the SSID “%p%s%s%s%s%n”, my iPhone permanently disabled it’s WiFi functionality. Neither rebooting nor changing SSID fixes it :~) [pic.twitter.com/2eue90JFu3](https://pic.twitter.com/2eue90JFu3)
>
> — Carl Schou (@vm_call) June 18, 2021

Looks like it's a format string bug, which is rarely seen nowadays.

Now set up a hotspot with the same SSID and use my test device to join, the wifid crashes soon.

Here's the symbolicated crash report `wifid-2021-06-20-xxxxxx.ips`

```
Thread 2 name:  Dispatch queue: com.apple.wifid.managerQueue
Thread 2 Crashed:
0   libsystem_platform.dylib      	0x00000001ebcb9724 _platform_strlen + 4
1   CoreFoundation                	0x00000001a381d84c __CFStringAppendFormatCore + 8812
2   CoreFoundation                	0x00000001a381efa8 _CFStringCreateWithFormatAndArgumentsReturningMetadata + 160
3   WiFiPolicy                    	0x00000001d0895f8c -[WFLogger WFLog:message:] + 192
4   ???                           	0x000000010692c00c 0 + 4405248012
5   wifid                         	0x0000000100f58a74 0x100e40000 + 1149556
6   wifid                         	0x0000000100f58c74 0x100e40000 + 1150068
```

So it's really a format string bug!

Decompile this function `-[WFLogger WFLog:message:]` in dyld_shared_cache. There are two references to `CFStringCreateWithFormatAndArguments`.

```objc
v7 = j__CFStringCreateWithCString_107(0LL, a4, 0x8000100u); // the format string
    if ( v7 || (v7 = j__CFStringCreateWithCString_107(0LL, a4, 0)) != 0LL )
    {
      if ( self->_destination == 2 )
      {
        v8 = j__CFStringCreateWithFormatAndArguments_26(0LL, 0LL, v7, v21);
        v18[3] = (__int64)v8;
      }
```

Another one

```objc
      if ( self->_destination != 2
        && (!self->_wflRunningOnWatchClassDevice || self->_wflEnableDualLoggingOnWatchClassDevice) )
      {
        *(_QWORD *)&v16.tm_sec = 0LL;
        *(_QWORD *)&v16.tm_hour = &v16;
        *(_QWORD *)&v16.tm_mon = 0x2020000000LL;
        *(_QWORD *)&v16.tm_wday = 0LL;
        v10 = j__CFStringCreateWithFormatAndArguments_26(0LL, 0LL, v7, v21); // <-- here
```

Debugging this issue with lldb will be painful because this method hits too often. Instead, attach frida to it: `frida-trace -U wifid -m '-[WFLogger WFLog:message:]'` and modify the auto-generated script a little:

```js
  onEnter(log, args, state) {
    const msg = '' + args[3].readUtf8String();
    log(`-[WFLogger WFLog:${args[2]} message:${msg}]`);
    if (msg.indexOf('%p%s%s%s%s%n') > -1) {
      for (let i = 3; i < 10; i++) {
        log(args[i], JSON.stringify(Process.findRangeByAddress(args[i])));
      }

      log('called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
    }
  },
```

Here's the log right before the crash.

> 17863 ms  -[WFLogger WFLog:0x3 message:Dequeuing command type: "%@" pending commands: %ld]
>
> 17863 ms  -[WFLogger WFLog:0x3 message:{ASSOC+} Attempting Apple80211AssociateAsync to %p%s%s%s%s%n]

According to the backtrace, this is the root cause:

```objc
v27 = sub_1000A25D4(v21);
v28 = objc_msgSend(
        &OBJC_CLASS___NSString,
        "stringWithFormat:",
        CFSTR("Attempting Apple80211AssociateAsync to %@"),
        v27);
v29 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("{ %@+} %@"), CFSTR("ASSOC"), v28);
v30 = objc_autoreleasePoolPush();
v31 = (void *)qword_100251888;
if ( qword_100251888 )
{
    v32 = objc_msgSend(v29, "UTF8String");
    objc_msgSend(v31, "WFLog:message:", 3LL, v32);
}
objc_autoreleasePoolPop(v30);
```

It concats the SSID to a format string and pass it to `WFLog:message:` method. Destination is 3 so it was the second xref of `CFStringCreateWithFormatAndArguments` that triggered the denial of service.

For the exploitability, it doesn't echo and the rest of the parameters don't seem like to be controllable. Thus I don't think this case is exploitable. After all, to trigger this bug, you need to connect to that WiFi, where the SSID is visible to the victim. A phishing Wi-Fi portal page might as well be more effective.
