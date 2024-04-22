---
layout:	post
title:  "Mistuned Part 3: PAC Bypass"
image:  /img/2021-08-04-mistuned-part-i/mistune.png
desc:   Bypass hardware assisted mitigation using Objective-C runtime.
---

In the previous parts, we have trigger use-after-free on Objective-C objects, and successfully refilled the dangling pointer with fully-controlled data. Now take a look at some prior research articles for further exploitation.

* [The Objective-C Runtime:  Understanding and Abusing](http://phrack.org/issues/66/4.html#article)
* [Modern Objective-C Exploitation Techniques](http://phrack.org/issues/69/9.html#article)
* [1933 - SLOP - A Userspace PAC Workaround - project-zero](https://bugs.chromium.org/p/project-zero/issues/detail?id=1933)

They all mentioned that `isa` member of Objective-C objects is a good target for explotation. The `isa` pointer is a pointer to the class object, and it is used to determine the class of an object, and it is used to dispatch messages to the correct method implementation.

SeLector Oritned Programming (SLOP) is a technique to abuse `isa` pointer to gain arbitrary code execution under PAC protection. The idea is to abuse the gadgets in `dealloc` implementation to call `invoke` method on a controlled object. By faking a `NSInvocation` object, we can call any method with arbitrary arguments and even control pc register by giving a fake `IMP` param. To make a series of calls, there will be an `NSArray` that contains multiple `NSInvocation` objects, and the `NSArray` is used to call `makeObjectsPerformSelector` method to invoke all the `NSInvocation` objects in the array one by one.

<p class="full"><img src="/img/2021-09-10-mistuned-part-iii/slop.svg" alt="SeLector Oriented Programming" /></p>

To protect Objective-C runtime, iOS 14 changed the ABI and started to sign `isa` pointer. The changes were not fully implemented, so isa only got signed but was not verified. SLOP still worked on iOS 14 until 14.5 finally shipped with PAC-ed `isa`.

In Part II, we managed to refill the dangling pointer with controllable data, but it's immutable after initialization. It's better to point the data to a JavaScript `ArrayBuffer`. The trick is to create a fake container type (e.g. `NSArray`) that points the element to JavaScript memory. For example, the structure of `__NSSingleObjectArrayI` is simply a isa pointer anda pointer to the only element in the array.

During TianfuCup, I was using heap spray. First I created a lot of `ArrayBuffer` objects that contain different fake `NSNumber` objects. So when I trigger the use-after-free and call `toString` on the fake `NSArray` object, it effectively tells me which `ArrayBuffer` is used to store the fake inner object.

<p class="full"><img src="/img/2021-09-10-mistuned-part-iii/heap-spray.svg" alt="Heap Spray"/></p>

<p class="full"><img src="/img/2021-09-10-mistuned-part-iii/nested-array.svg" alt="Nested Array Structure"/></p>

Heap spray is less reliable. Just few weeks after TianfuCup, I realized that I can totally get ride of it. At this moment, we already have ASLR bypass to leak arbitrary `isa` pointer and `addrof` primitive to get the heap address of `NSObject` exported to JavaScript world. Addictionaly, using `toString` on a fake `NSData` object gives a binary safe arbitrary read primitive.

<img src="/img/2021-09-10-mistuned-part-iii/pac-cage.svg" alt="PAC Cage" />

So first create an `ArrayBuffer` to reserve enough space for fake objects. `addrof(arrayBuffer)` leaks the heap address of the corresponding `WebScriptObject`. Read its `jsObject` member gives another heap address to `Int8Array` object, whose `VectorPtr` member will be the PAC-ed address to the content of the `ArrayBuffer`. Just simply strip the high bits. Now we can reuse this memory for various fake objects.

After Project Zero's iMessage research, `NSInvocation` has introduced a 32bit random `_magic_cookie`, but it can be bypassed using arbitrary read.

To build the whole SLOP chain, we need to call `dealloc` on fake NSObject twice. Once for reclaiming the memory to build fake objects, then the second time is to kickstart the code execution chain.

The `invoke` gadget we used is `-[SKStoreReviewViewController dealloc]` method. However, this class is not a subclass of `SUScriptObject`. So after we replace the dangling object with a while SLOP chain, we can't simply call `delloc` on it with JavaScript.

The solution is to abuse `SUScriptSegmentedControlItem` gadget. It has a property setter `setUserInfo:` which accepts arbitrary `SUScriptObject`. Upon the deallocation of this class, it will call `dealloc` on the `userInfo` object we associated with.

```javascript
const deallocator = iTunes.makeSegmentedControl();
const seg = deallocator.createSegment(); // for double free
iTunes.log(`dangling pointer: ${addrof(x)}`);
window.x = x; // avoid GC
seg.setUserInfo_(x);
x.dealloc(); // first free
// ... memory R/W and prepare for SLOP
seg.dealloc(); // double free to kickstart the chain
```

By combinating `-[CNFileServices dlsym::]` and `-[NSInvocation invokeUsingIMP:]`, we can sign arbitrary exported function and invoke them. Those gadgets were still available on iOS 14.3.

There was one problem that wasn't solved by Project Zero's publication, that due to the limitation of `NSInvocation`, the first argument of the method must not be 0 (`NULL`). I solved the problem by using `CFSetApplyFunction` callbacks.

```c
void *fake[2] = {(__bridge void *)NSClassFromString(@"__NSSingleObjectSetI"), NULL};
CFSetApplyFunction((void *)&fake[0], (void*)exit, (void*)0x41414141);
```

We can deploy almost everything with SLOP chain. But since this context has `dynamic-codesigning` entitlement, it's better to have full shellcode.

On iOS 14.3, somehow `performJITMemcpy` was not inlined. There was even a public symbol `pthread_jit_write_protect_np`, making the exploit extremely simple.

Finally another PAC bypass was involved to jump to the shellcode. This step was totally unnecessary, but just to flex.

In `/usr/lib/swift/libswiftDarwin.dylib`, the global offset table was not protected. This following code path could be reached from `_$s6Darwin2jnySdSi_SdtF`, which could be resolved by `dlsym`:

```
; Darwin.jn(Swift.Int, Swift.Double) -> Swift.Double
               EXPORT _$s6Darwin2jnySdSi_SdtF
_$s6Darwin2jnySdSi_SdtF
               ADRP      X1, #_jn_ptr@PAGEOFF
               LDR       X1, [X1,#_jn_ptr@PAGEOFF] ; <-- load raw function pointer
               B         _$s6Darwin2jnySdSi_SdtFTm ; jn(_:_:)

; merged Darwin.jn(Swift.Int, Swift.Double) -> Swift.Double
_$s6Darwin2jnySdSi_SdtFTm ; CODE XREF: jn(_:_:)+8↑j
               ; yn(_:_:)+8↑j
               TBNZ      X0, #0x3F, loc_1B5E9832C ; '?'
               CMP       X0, W0,SXTW
               CSET      W8, NE
               CMP       W0, #0
               CSET      W9, LT
               MOV       W10, #0x80000000
               CMP       X0, X10
               B.LT      loc_1B5E98338
               ORR       W8, W8, W9
               TBZ       W8, #0, loc_1B5E98338
               BRK       #1
; ---------------------------------------------------------------------------
loc_1B5E9832C                     ; CODE XREF: jn(_:_:)↑j
               MOV       X8, #0xFFFFFFFF80000000
               CMP       X0, X8
               B.LT      loc_1B5E9833C
loc_1B5E98338                     ; CODE XREF: jn(_:_:)+1C↑j
                                  ; jn(_:_:)+24↑j
               BR        X1  ; <-- unprotected jump
```

The final result:

<img src="/img/2021-09-10-mistuned-part-iii/registers.png" alt="Pwned Registers" style="width: 480px"/>
