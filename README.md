# Awesome Apple Security List [![Awesome](https://awesome.re/badge-flat.svg)](https://awesome.re)

> Curated list of tools, techniques and resources related to Apple Security (macOS, iOS, iPadOS, tvOS, watchOS) aimed to help people with an interest in Apple related cyber security topics to gain a foothold in this field.

## Contents

- [Awesome Apple Security List ](#awesome-apple-security-list-)
  - [Contents](#contents)
  - [Forensics](#forensics)
    - [Acquisition and Evidence Collection](#acquisition-and-evidence-collection)
  - [Apple Guidance](#apple-guidance)
  - [Attack Vectors and Adversary Techniques](#attack-vectors-and-adversary-techniques)
  - [Blogs](#blogs)
  - [Articles](#articles)
  - [Books and Magazines](#books-and-magazines)
  - [People](#people)
  - [Software Collections](#software-collections)
  - [Malware](#malware)
  - [Hardware Information](#hardware-information)
  - [Log Analysis](#log-analysis)
  - [Processes](#processes)
  - [Persistence](#persistence)
  - [Tools](#tools)
    - [Process Viewer](#process-viewer)
    - [File System](#file-system)
    - [Offensive Tools](#offensive-tools)
    - [Reverse Engineering Tools](#reverse-engineering-tools)
    - [Dynamic Analysis Tools](#dynamic-analysis-tools)
    - [Static Analysis Tools](#static-analysis-tools)
    - [Frida](#frida)
  - [Conferences](#conferences)
  - [Trainings](#trainings)
  - [Videos](#videos)
  - [Contributing](#contributing)

---
## Forensics

### Acquisition and Evidence Collection

- [Cellebrite Digital Collector (Former Macquisition)](https://cellebrite.com/en/digital-collector/) - Commercial Tooling for Acquisition of macOS Forensic Images.
- [mac_apt](https://github.com/ydkhatri/mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
- [Auditor](https://github.com/jipegit/OSXAuditor) - Deprecated macOS DFIR tool for older systems.
- [Collector](https://github.com/yelp/osxcollector) - macOS offshoot for live response.
- [The ESF Playground](https://themittenmac.com/the-esf-playground/) - A tool to view the events in Apple Endpoint Security Framework (ESF) in real time.


## Apple Guidance

- [Developers Documentation](https://developer.apple.com/documentation/foundation?preferredLanguage=oc) - Developer Documentation for reference.
- [Security Documentation](https://support.apple.com/en-gb/guide/security/welcome/we) - Security Documentation of Apple Products.
- [Report Vulnerabilities](https://support.apple.com/en-gb/HT20122) - In case you want to submit a vulnerability to Apple.
- [Apple Security Bounty](https://developer.apple.com/security-bounty) - Apple's Bug Bounty Program information.
- [Apple Platform Security](https://manuals.info.apple.com/MANUALS/1000/MA1902/en_GB/apple-platform-security-guide-b.pd) - Apple Information on Platform Security.
- [Apple File System](https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system) - Documentation on the filesystem.

## Attack Vectors and Adversary Techniques

- [MITRE ATT&CK - macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/) - Tools, Techniques and Attack Vectors used by adversaries to target macOS devices.
- [Sandbox Evasion Macros](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) - How to evade the sandbox with MS Office Macros.

## Blogs

- [Mac Security Blog](https://www.intego.com/mac-security-blog/) - Generic Blog on macOS Security.
- [Wojciech Regula's Blog](https://wojciechregula.blog/post/) - Wojciech's macOS Related blog.
- [Cedric Owens Medium Blog](https://cedowens.medium.com) - Cedric Owens Blog on macOS Security. 
- [Objective-See by Patrick Wardle](https://objective-see.com/) - Patrick Wardle's Website.
- [Mac4n6](https://www.mac4n6.com/) - Mac Forensics.
- [Mandiant](https://www.mandiant.com/search?search=macos) - Mandiant macOS Articles.

## Articles

- [RE Cocoa Applications](https://www.mandiant.com/resources/blog/introduction-to-reve) - 
- [Office365 Sanbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) - Sandbox Escape macOS for Office365.


## Books and Magazines

- [The Art of Mac Malware](https://taomm.org/) - Primer on malware on macOS by Patrick Wardle.
- [macOS Incident Response](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS) - macOS Incident Response primer (2017).
- [Kernel Book](http://newosxbook.com/index.php) - Book in three parts about the macOS Kernel.
- [macOS Internals](https://www.amazon.com/Mac-OS-Internals-Systems-Approach-ebook/dp/B004Y4UTLI/) - Internals of macOS (2007).
- [Kernel Programming](https://www.amazon.com/OS-X-iOS-Kernel-Programming/dp/1430235365/) - Kernel Programming reference for macOS / iOS.
- [eForensics Magazine](https://eforensicsmag.com/product/macos-forensics/) - Magazine for (macOS) Forensics.
- [iOS Forensics for Investigators](https://www.amazon.com/iOS-Forensics-Investigators-forensics-extracting-ebook-dp-B09V19ZBKK/dp/B09V19ZBKK/ref=mt_other?_encoding=UTF8&me=&qid=) - iOS Forensics Book.
- [iOS Hacking Guide](https://web.securityinnovation.com/hacking-ios-applications) - By Security Innovation.
- [iOS Application Security: The Definitive Guide for Hackers and Developers](https://nostarch.com/iossecurity) - By David Thiel.
- [iOS Penetration Testing: A Definitive Guide to iOS Security](https://link.springer.com/book/10.1007/978-1-4842-2355-0) - By Kunal Relan.
- [Learning iOS Penetration Testing](https://www.packtpub.com/product/learning-ios-penetration-testing/9781785883255) - By Swaroop Yermalkar.
- [Hacking and Securing iOS Applications](https://www.oreilly.com/library/view/hacking-and-securing/9781449325213/) - By Jonathan Zdziarski.
- [iOS Hacker's Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123) - By Charlie Miller.


## People

- [Cedric Owens](https://twitter.com/cedowens) - X - macOS Security Researcher and Purple Teamer.
- [Csaba Fitzl](https://twitter.com/theevilbit) - X - Hungarian Researcher specialized on macOS Security.
- [Patrick Wardle](https://twitter.com/patrickwardle) - X - Founder of Objective-see, and Security Researcher.
- [Sarah Edwards](https://twitter.com/iamevltwin) - X - Security Researcher and Trainer of SANS 518 Course.
- [Cody Thomas](https://github.com/its-a-feature) - GitHub - Developer of Mythic C2.
- [Regula Wojciech](https://x.com/_r3ggi) - X - macOS Security Researcher.
- [Alexis Brignoni](https://infosec.exchange/@abrignoni) - X - DFIR Researcher, iLEAPP Developer.
- [M4shl3](https://hackmd.io/@M4shl3) - hackmd.io - Digital Forensics Investigator.

## Software Collections
- [Macintosh Repository](https://www.macintoshrepository.org/) - Repository of old macOS Software.

## Malware

- [The Safe Mac](https://www.thesafemac.com/mmg-catalog/) - Older macOS Malware Catalogue.
- [VX-Underground](https://www.vx-underground.org/archive/VxHeaven/vl.php.html) - Malware Collection (various OS).
- [VX-Underground Malware Source Code](https://github.com/vxunderground/MalwareSourceCode) - Malware Sourcecode collection (various OS).
- [Objective-See Malware](https://github.com/objective-see/Malware) - Malware Collection by Patrick Wardle.

## Hardware Information

- [Hardware Database](https://everymac.com/) - Lookup hardware specifications of every mac model.
- [M1 Chip Safe Mode](https://eclecticlight.co/2022/01/17/what-does-safe-mode-do-to-an-m1-mac/) - Blogpost on M1 Chipset Safe Mode.

## Log Analysis

- [Unified Log](https://eclecticlight.co/2018/03/20/macos-unified-log-2-content-and-extraction/) - A primer on macOS Unified Log.
- [Unified Log in Incident Response](https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response/) - Using the Unified Log for Incident Response.


## Processes

- [True Tree](https://themittenmac.com/the-truetree-concept/) - Improved process tree.
- [Process and File Monitor](https://objective-see.com/products/utilities.html) - Command Line Utilit(ies) to monitor processes and files.

## Persistence

- [Persistence Samples](https://theevilbit.github.io/categories/persistence/) - Collection of persistence methods and samples used.
- [Knockknock](https://objective-see.com/products/knockknock.html) - Displays persistence items in macOS.
- [PersistentJXA](https://github.com/D00MFist/PersistentJXA) - Collection of macOS persistence methods in JXA.
- [Apple Persistence Mechanisms](https://gist.github.com/jipegit/04d1c577f20922adcd2cfd90698c151b) - Persistence Mechanisms.

## Tools

### Process Viewer

- [Process Tree](https://github.com/ydkhatri/mac_apt/tree/729630c8bbe7a73cce3ca330305d3301a919cb07) - Process tree Repository.

  
### File System

- [iOS FS Event Parser](https://github.com/dlcowen/FSEventsParser) - Parsing filesystem events.
- [FS Monitor](https://fsmonitor.com/) - FS Monitor to view live file system changes.
- [macOS FS Events Parser](https://github.com/mac4n6/FSEventsParser) - FS Events Parser.

### Offensive Tools

- [Mythic C2](https://docs.mythic-c2.net/) - Mythic C2 Framework Documentation.
- [VOODOO](https://github.com/breakpointHQ/VOODOO) - Browser Attack Framework for macOS.
- [SwiftSpy](https://github.com/slyd0g/SwiftSpy) - macOS Keyloger written in Swift.

### Reverse Engineering Tools

- [Hopper](https://www.hopperapp.com/) - A reverse engineering tool that will assist you in your static analysis of executable files.
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - A software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate.
- [Radare2](https://github.com/radareorg/radare2) - UNIX-like reverse engineering framework and command-line toolset.
- [Cutter](https://github.com/rizinorg/cutter) - Free and Open Source Reverse Engineering Platform powered by rizin.
- [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) - A tool to pull a decrypted IPA from a jailbroken device.
- [bagbak](https://github.com/ChiChou/bagbak) - Yet another frida based App decryptor. Requires jailbroken iOS device and frida.re.
- [flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - An iOS App & Mach-O binary decryptor.
- [bfdecrypt](https://github.com/BishopFox/bfdecrypt) - Utility to decrypt App Store apps on jailbroken iOS 11.x.
- [bfinject](https://github.com/BishopFox/bfinject) - Easy dylib injection for jailbroken 64-bit iOS 11.0 - 11.1.2. Compatible with Electra and LiberiOS jailbreaks.
- [r2flutch](https://github.com/as0ler/r2flutch) - Yet another tool to decrypt iOS apps using r2frida.
- [Clutch](https://github.com/KJCracks/Clutch) - A high-speed iOS decryption tool.
- [dsdump](https://github.com/DerekSelander/dsdump) - An improved nm + objc/swift class-dump tool.
- [class-dump](https://github.com/nygard/class-dump) - A command-line utility for examining the Objective-C segment of Mach-O files.
- [SwiftDump](https://github.com/neil-wu/SwiftDump/) - A command-line tool for retriving the Swift Object info from Mach-O file.
- [jtool](http://www.newosxbook.com/tools/jtool.html) - An app inspector, disassembler, and signing utility for the macOS, iOS.
- [Sideloadly](https://sideloadly.io/) - An app to sideload your favorite games and apps to Jailbroken & Non-Jailbroken iOS devices.
- [Cydia Impactor](http://www.cydiaimpactor.com/) - A GUI tool for sideloading iOS application.
- [AltStore](https://altstore.io/) - Allows to sideload other apps (.ipa files) onto iOS device.
- [iOS App Signer](https://github.com/DanTheMan827/ios-app-signer) - An app for macOS that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.

### Dynamic Analysis Tools

- [Corellium](https://www.corellium.com/) - The only platform offering ARM-based mobile device virtualization using a custom-built hypervisor for real-world accuracy and high performance.
- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
- [frida-gum](https://github.com/frida/frida-gum) - Cross-platform instrumentation and introspection library written in C.
- [Fridax](https://github.com/NorthwaveSecurity/fridax) - Fridax enables you to read variables and intercept/hook functions in Xamarin/Mono JIT and AOT compiled iOS/Android applications.
- [r2frida](https://github.com/nowsecure/r2frida) - Radare2 and Frida better together.
- [r2ghidra](https://github.com/radareorg/r2ghidra) - An integration of the Ghidra decompiler for radare2.
- [iproxy](https://github.com/libimobiledevice/libusbmuxd) - A utility allows binding local TCP ports so that a connection to one (or more) of the local ports will be forwarded to the specified port (or ports) on a usbmux device.
- [itunnel](https://code.google.com/archive/p/iphonetunnel-usbmuxconnectbyport/downloads) - Use to forward SSH via USB.
- [objection](https://github.com/sensepost/objection) - A runtime mobile exploration toolkit, powered by Frida, built to help you assess the security posture of your mobile applications, without needing a jailbreak.
- [Grapefruit](https://github.com/ChiChou/grapefruit) - Runtime Application Instruments for iOS.
- [Passionfruit](https://github.com/chaitin/passionfruit) - Simple iOS app blackbox assessment tool, powered by frida 12.x and vuejs.
- [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - Runtime Mobile Security (RMS), powered by FRIDA, is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime.
- [membuddy](https://zygosec.com/membuddy.html) - Dynamic memory analysis & visualisation tool for security researchers.
- [unidbg](https://github.com/zhkl0228/unidbg) - Allows you to emulate an Android ARM32 and/or ARM64 native library, and an experimental iOS emulation.
- [Qiling](https://github.com/qilingframework/qiling) - An advanced binary emulation framework.
- [fishhook](https://github.com/facebook/fishhook) - A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [Dwarf](https://github.com/iGio90/Dwarf) - Full featured multi arch/os debugger built on top of PyQt5 and frida.
- [FridaHookSwiftAlamofire](https://github.com/neil-wu/FridaHookSwiftAlamofire) - A frida tool that capture GET/POST HTTP requests of iOS Swift library 'Alamofire' and disable SSL Pinning.
- [ios-deploy](https://github.com/ios-control/ios-deploy) - Install and debug iOS apps from the command line. Designed to work on un-jailbroken devices.
- [aah](https://github.com/zydeco/aah) - Run iOS arm64 binaries on x86_64 macOS, with varying degrees of success.
- [LLDB](https://lldb.llvm.org/) - A next generation, high-performance debugger. 
- [mitmproxy](https://mitmproxy.org/) - A free and open source interactive HTTPS proxy.
- [Burp Suite](https://portswigger.net/burp) - An advanced HTTPS proxy software.

### Static Analysis Tools

- [iLEAPP](https://github.com/abrignoni/iLEAPP) - An iOS Logs, Events, And Plist Parser.
- [Keychain Dumper](https://github.com/ptoomey3/Keychain-Dumper) - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- [BinaryCookieReader](https://github.com/as0ler/BinaryCookieReader) - A tool to read the binarycookie format of Cookies on iOS applications.
- [PList Viewer](https://github.com/TingPing/plist-viewer) - Gtk application to view property list files.
- [XMachOViewer](https://github.com/horsicq/XMachOViewer) - A Mach-O viewer for Windows, Linux and macOS.
- [MachO-Explorer](https://github.com/DeVaukz/MachO-Explorer) - A graphical Mach-O viewer for macOS. Powered by Mach-O Kit.
- [iFunbox](https://www.i-funbox.com/en/index.html) - A general file management software for iPhone and other Apple products.
- [3uTools](http://www.3u.com/) - An All-in-One management software for iOS devices.
- [iTools](https://www.thinkskysoft.com/itools/) - An All-in-One solution for iOS devices management.

### Frida

- [FridaSwiftDump](https://github.com/neil-wu/FridaSwiftDump/) - A Frida script for retriving the Swift Object info from an running app.
- [iOS 13 SSL Bypass](https://codeshare.frida.re/@federicodotta/ios13-pinning-bypass/) - SSL Pinning Bypass for iOS 13.
- [iOS 12 SSL Bypass](https://codeshare.frida.re/@machoreverser/ios12-ssl-bypass/) - SSL Pinning Bypass for iOS 12.
- [iOS Jailbreak Detection Bypass](https://codeshare.frida.re/@liangxiaoyi1024/ios-jailbreak-detection-bypass/) - A Frida script used for bypass iOS jailbreak detection by hooking some methods and functions.
- [iOS App Static Analysis](https://codeshare.frida.re/@interference-security/ios-app-static-analysis/) - Script for iOS app's static analysis.
- [Touch ID Bypass](https://highaltitudehacks.com/2018/07/26/ios-application-security-part-50-touch-id-bypass-with-frida/) - A Frida script for iOS Touch/Face ID Bypass.

## Conferences

- [MacDevOps YVR](https://mdoyvr.com)
- [OBTS](https://objectivebythesea.org)

## Trainings

- [OffSec EXP-312](https://www.offsec.com/courses/exp-312/) - Advanced macOS Control Bypass Trainin by OffSec's @theevilbit.
- [Sumuri](https://sumuri.com/mac-training/) - Forensics Training in two parts for macOS, to gain Certified Forensic Mac Examiner Certification.
- [SANS 518](https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/) - Course at SANS for macOS and iOS Forensics.
- [Objective-by-the-sea](https://objectivebythesea.org/v5/index.html) - Security Conference (macOS) organized by Patrick Wardle.
- [SpecterOPS](https://specterops.io/training/mac-tradecraft/) - SPECTEROPS macOS Adversary Tactics.
- [Pentesting iOS Applications](https://www.pentesteracademy.com/course?id=2) - By PentesterAcademy.
- [iOS Pentesting](https://www.youtube.com/playlist?list=PL5Fxd3nu70eyqiqrVlD9QMoaOARr082TA) - By Mantis.
- [iOS Application Pentesting Series](https://www.youtube.com/playlist?list=PLm_U3e1sSTMvgj1sbZ2Ng6VbxMWw8Wyk9) - By Sateesh Verma.
- [IOS: Penetration Testing](https://www.youtube.com/playlist?list=PLanZMaPa4zzyGJ7IiW2zQNC40pWf2-7uE) - By Noisy Hacker.
- [JAMF 100 Course](https://www.youtube.com/watch?v=DsaWL0xzs6o&list=PLWs1qukS_mcb1wwKeSnT80kvTKow_eJXJ) - JAMF 100 Youtube Playlist.

## Videos

- [Curated YouTube Playlist](https://www.youtube.com/playlist?list=PL-zBXVr8oElPpEuhuTON7qE4k6iVh0zMv) - Curated YouTube playlist with macOS/iOS Security Topics.

## Contributing

Your contributions are always welcome! Please read the [contribution guidelines](contributing.md) first.
