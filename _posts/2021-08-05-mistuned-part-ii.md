---
layout:	post
title: "Mistuned Part 2: Butterfly Effect"
image: /img/2021-08-04-mistuned-part-i/mistune.png
---

In the last post, I used a client-side XSS to get JavaScript injected to a local pre-installed app. It has no process isolation while it still supports in-process just-in-time (JIT). Any working WebKit exploit works there too, with much more access than WebContent renderer. It doesn’t even need real code execution to launch Calculator app.

Trolling is not the goal. Let’s try harder.

As we’ve mentioned before, the WebView has some Objective-C methods exposed to JavaScript under the `iTunes` namespace. The corresponding interfaces are implemented by an `SUScriptInterface` instance.

This is powered by the obsolete [WebScripting](https://developer.apple.com/documentation/objectivec/nsobject/webscripting) API. It does automatically type convention between JavaScript (JSValue) and NSObject.

However, an insufficient access control leads to exploitable bugs. The bug introduced by iOS 6 only has two instructions altogether.

```objective-c
bool +[SUScriptObject isSelectorExcludedFromWebScript:](id, SEL, SEL)
  MOV             W0, #0
  RET
```

What could possibly go wrong?

According to the [documentation](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/SafariJSProgTopics/ObjCFromJavaScript.html):

> For security reasons, no methods or KVC keys are exposed to the JavaScript environment by default. Instead a class must implement these methods:
>
>  * `+ (BOOL)isSelectorExcludedFromWebScript:(SEL)aSelector;`
>  * `+ (BOOL)isKeyExcludedFromWebScript:(const char *)name;`
>
> The default is to exclude all selectors and keys. Returning NO for some selectors and key names will expose those selectors or keys to JavaScript. This is described further in  [WebKit Plug-In Programming Topics](https://developer.apple.com/library/archive/documentation/InternetWeb/Conceptual/WebKit_PluginProgTopic/WebKitPluginTopics.html#//apple_ref/doc/uid/TP40001521) .

By returning `NO` for every selector, all of the methods are visible to JavaScript.

## Primitive `addrof`

Objective-C programming is about messaging. When an Objective-C instance receives an unknown selector, it throws an `NSException` like this: 

> unrecognized selector sent to instance `0x10b15a470`

The address is usually the heap pointer of the object.

Method `scriptWindowContext` and `setScriptWindowContext_` are the setter and getter for `iTunes.window` object respectively. They are not supposed to be used by JavaScript. With the access control policy, it’s possible to use the setter to assign any object to that property, causing a potential runtime type confusion.

In `-[SUScriptInterface window]` function, it performs the `tag` selector on that object. If the object doesn't recognize the selector, it throws an exception that is catchable by Javascript. We can read the hexlified heap address of the object out of `Error.message`.

```javascript
function addrof(obj) {
  const saved = iTunes.scriptWindowContext()
  iTunes.setScriptWindowContext_(obj)
  try {
    iTunes.window
  } catch(e) {
    console.debug(e)
    const match = /instance (0x[\da-f]+)$/i.exec(e)
    if (match) return match[1]
    throw new Error('Unable to leak heap addr')
  } finally {
    iTunes.setScriptWindowContext_(saved)
  }
}

// usage:
addrof(iTunes.makeWindow())
addrof('A'.repeat(1024 * 1024))
```

This primitive is never seen before and it only applies to this particular application.

## ASLR Bypass

Now we immediatly bypass ASLR with the same primitive. The Objective-C runtime uses various tricks to save memory, e.g., tagged pointer, class clusters, etc. Some of the magic values does not create new object instance at all. They use shared instances instead.

* `__kCFNumberNaN`: `NaN`
* `__kCFNumberPositiveInfinity`: `Infinity`
* `__kCFBooleanTrue`: `true`
* `__kCFBooleanFalse`: `false`

So `addrof(false)` leaks the address of `__kCFBooleanFalse`, which is in the CoreFoundation library. All of the system libraries are linked together in a huge dyld_shared_cache, so the they share the same slide.

## Use-After-Free

Lack of access control leads to unexpected behavior that some critical methods that control the object lifecycle are now accessible. For example, the equivalent of `free` in Objective-C is the `dealloc` method.

Just ask the interface to allocate an object and call its deallocation method, now we have a dangling reference to it:

```javascript
const w = iTunes.makeWindow();
w.dealloc();
w // dangling reference
```

This results in an access voilation within the runtime function `objc_opt_respondsToSelector` that the runtime tries to dereference an invalid id pointer.

![dangling pointer](/img/2021-08-05-mistuned-part-ii/uaf.svg)

This bug was introduced by iOS 6. It has been assigned to CVE-2021-1864.

## Reclaiming the Memory
Now it’s time for classic UAF exploitation. Refill the memory with another differently shaped object to make a type confusion.

All the subclasses of `SUScriptObject` have the `deallloc` method exported. There are plenty of `-[SUScriptInterface make*]` methods that allocate new instance for various of `SUScriptObject`, making them the ideal subjects to create dangling pointers. Here we chose `makeXMLHTTPStoreRequest` because the size of the object returned is big enough for not easily having collision with other common allocations.

The problem is that variant size objects in JavaScriptCore have their own heap, making it impossible to reclaim the freed memory with ArrayBuffer or JavaScript string.

Luckily I found this method `addMultiPartData:withName:type:` in `SUScriptFacebookRequest` class. The first argument is a string to lately create an `NSURL`. When the URL scheme is `data:`, it calls `SUGetDataForDataURL` to decode the payload to create an `NSData` with fully controlled length and content. This makes an incredibly perfect `malloc` primitive in the desired heap and it's even binary-safe. Every single bytes, including the `isa` pointer are fully customizable.

![fakeobj](/img/2021-08-05-mistuned-part-ii/fakeobj.jpg)

Now the challenge is, how do we exploit this on PAC devices? Stay tuned for the next posts.

## Conclusion

This bug is so unique. It wouldn’t be possible to reached the code without the first XSS. It's considered unfuzzable. Although `dealloc` does make the app crash, the methods are not enumerable by JavaScript unless we know the exact names.

The funny thing is that there is a clear security warning in the documentation about how developers should deal with the method, but the code still went wrong. It makes me think that even given the machine enough intelligence and power to explore program states, some mistakes are still hard for them and even us human to understand. That's why we need offensive research.
