# CVEs
- CVE-2015-5525 - Unsecured Unix Socket/IPC to root process for eapd
- CVE-2015-5526 - Path transversal in eapd
- CVE-2015-5527 - Backdoor for executing shell scripts as root

## Authors
- Jon “jcase” Sawyer - jcase@cunninglogic.com
- Tim “diff” Strazzere - strazz@gmail.com

## Affected Devices (tested on)
- HTC Desire 310
- Likely other HTC devices

## CVE-2015-5525
`init` starts the process `/system/bin/eapd`, which runs as root. This process’s entire purpose is to run shell scripts as the root user.
This process listens for input on a socket that is world readable and writable. This socket should be protected by more strict permissions,
and/or a SELinux policy (and eapd likely shouldn’t exist).

```
srw-rw-rw- root     system            2015-08-04 15:22 eapd
```

## CVE-2015-5526

The `eapd` process (`/system/bin/eapd`) is vulnerable to a path transversal vulnerability, when combined with CVE-2015-5525 this results in any app/user being able to execute a script as the root user. Input should be sanitized (and eapd shouldn't exist). By attaching to the `eapd` socket, which this process listens on, the user can craft a directory traversal to a file that they control.

Simplified;
`sprintf(path,"%s%s%s", "/data/data/com.cci.eapenhance/cache/", input, ".sh"`

```
loc_B30
LDR             R1, =(a_sh - 0xB3E)
ADD             R6, SP, #0x220+var_C4
LDR             R2, =(aSSS - 0xB42)
MOV             R0, R6  ; char *
LDR             R3, =(aDataDataCom_cc - 0xB46)
ADD             R1, PC ; a_sh ; ".sh"
STR             R7, [SP,#0x220+var_220]
ADD             R2, PC  ; "%s%s%s"
STR             R1, [SP,#0x220+var_21C]
ADD             R3, PC  ; "/data/data/com.cci.eapenhance/cache/"
MOVS            R1, #0x96 ; size_t
BLX             snprintf
LDR             R2, =(aScript_pathS - 0xB56)
MOV             R1, R5
MOV             R3, R6
MOVS            R0, #6
ADD             R2, PC  ; "script_path = %s"
BLX             __android_log_print
LDR             R1, =(aR - 0xB60)
MOV             R0, R6  ; char *
ADD             R1, PC  ; "r"
BLX             fopen
MOV             R9, R0
CBZ             R0, loc_BAA
```

The below code simply performs;
`system(path)`

```
LDR             R2, =(aSS - 0xB74)
MOVS            R1, #0x96 ; size_t
LDR             R3, =(aSystemBinSh - 0xB76)
ADD             R0, SP, #0x220+var_15C ; char *
STR             R6, [SP,#0x220+var_220]
ADD             R2, PC  ; "%s %s"
ADD             R3, PC  ; "/system/bin/sh"
BLX             snprintf
LDR             R2, =(aCmdS - 0xB84)
MOV             R1, R5
ADD             R3, SP, #0x220+var_15C
MOVS            R0, #6
ADD             R2, PC  ; "cmd========================%s"
BLX             __android_log_print
ADD             R0, SP, #0x220+var_15C ; char *
BLX             system
MOV             R0, R9  ; FILE *
BLX             fclose
MOV             R0, R6  ; char *
BLX             remove
ADD             R0, SP, #0x220+var_15C ; void *
MOVS            R1, #0  ; int
MOVS            R2, #0x96 ; size_t
BLX             memset
```

## CVE-2015-5527

The application `/system/app/EAP_SU.apk`, package name `com.cci.eapsu`, has an unprotected Broadcast Receiver that acts a backdoor. This allows
ab unprivledged user to execute shell commands as root through `eapd` without relying on the two previous CVEs. This may be exploited from an
app or adb using a broadcast containing the script in an extra named 'cmd'. The broadcast receivers should be protected with a strict permission,
 hoever in reality EAP_SU and eapd should not exist as they are outside of the normal Andorid permission model.

Vulnerable manifest;
```
<manifest
    android:sharedUserId="android.uid.system"
    android:versionCode="2"
    android:versionName="1.1"
    package="com.cci.eapsu"
    xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        <receiver android:name=".CmdReceiver">
            <intent-filter>
                <action android:name="com.cci.eapsu.DoSuCmd" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

Vulnerable code;
```
public class CmdReceiver extends BroadcastReceiver {
    private final String DO_SU_CMD;
    static final String TAG = "EAP_SU";
    private String cmd;

    public CmdReceiver() {
        super();
        this.DO_SU_CMD = "com.cci.eapsu.DoSuCmd";
        this.cmd = "";
    }

    protected static boolean DoSuCmd(String arg8) {
        boolean v4 = false;
        SystemProperties.set("ctl.stop", "my_su_command");
        Log.d("EAP_SU", "doCmdByDaemon - cmd = " + arg8);
        String CmdPath = "/data";
        String CmdName = "cmd.sh";
        if(PlatformFeatures.getPlatformID() == 80 || PlatformFeatures.getPlatformID() == 66) {
            CmdName = "command.sh";
        }

        File fileScript = new File(CmdPath, CmdName);
        if(fileScript.exists()) {
            fileScript.delete();
        }

        if(!FileOperations.writeStrToFile(fileScript.getAbsolutePath(), arg8, false)) {
            if(fileScript.exists()) {
                fileScript.delete();
            }

            Log.e("EAP_SU", "Write " + CmdPath + "/" + CmdName + " script Fail!!");
        }
        else {
            SystemProperties.set("ctl.start", "my_su_command");
            v4 = true;
        }

        return v4;
    }

    public void onReceive(Context arg4, Intent arg5) {
        if(arg5.getAction().equals("com.cci.eapsu.DoSuCmd")) {
            this.cmd = arg5.getExtras().getString("cmd");
            Log.d("EAP_SU", "onReceive cmd: " + this.cmd);
            CmdReceiver.DoSuCmd(this.cmd);
        }
    }
}
```
