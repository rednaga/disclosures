# disclosures

## CVEs

- ["Get Super Serial" CVE-2015-2231 & CVE-2015-2232](https://github.com/rednaga/disclosures/blob/master/GetSuperSerial.md)
  
  Chain from an application with internet permissions to a system uid, then from a system uid to root. This is mainly due
  to an extremely weak firmware upgrade system calls "ADUPS" which has failed to have any type of response. While the two
  specific CVEs directly correlate to a few Blu phones, it appears to be used by many other lower-end phones.


- ["HTC Peap" CVE-2015-5525, CVE-2015-5526 & CVE-2015-5527](https://github.com/rednaga/disclosures/blob/master/HTCPeap.md)
  
  Multiple ways to access a backdoor which allows an unprivledged application the ability to run root commands. Discussed
  at the DEFCON23 Red Naga workshop on Offensive and Defensive Android Reverse Engineering.

- ["Qualcomm System Agent", No CVEs assigned](https://github.com/rednaga/disclosures/blob/master/QCOMSysAgent.md)

  Multiple vulnerabilities in an application that was never meant to be shipped on production devices. Discussed
  at the DEFCON23 Red Naga workshop on Offensive and Defensive Android Reverse Engineering.
  
- ["Blackphone 1 modem take over", CVE-2015-6841](https://www.sentinelone.com/blog/vulnerability-in-blackphone-puts-devices-at-risk-for-takeover/)

  Allows any local attacker to take over the modem, inject commands, cause denial of service and other creepy things.
  [Vendor Post](https://www.silentcircle.com/blog/blackphone-1-vulnerability-notice/), [release notes](https://support.silentcircle.com/customer/en/portal/articles/2242250-privatos-1-1-13-release-notes?b_id=4315).

- ["RESERVED", RED-2016-0029 / CVE-2016-????]()

  Triaged by Google as Critical/Severe. RCE seems not possible on 4.2+ devices due to mitigations in place,
  however remote DOS/crash still available without interaction. More details and CVE after fix is released.

- ["RESERVED", RED-2016-0030 / CVE-2016-????]()

  Spot reserved for arbitraty (blind) system command execution on newly (7/2016) released Android 6 device.
  Details and CVE listed after vendor fix and assigned.
