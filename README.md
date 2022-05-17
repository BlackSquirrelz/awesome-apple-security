# Apple Security List [![Awesome](https://awesome.re/badge-flat.svg)](https://awesome.re)

> Curated list of tools, techniques and resources related to Apple Security (macOS, iOS, iPadOS, tvOS, watchOS) aimed to help people with an interest in Apple related cyber security topics to gain a foothold in this field.

## Contents

- [Acquisition and Evidence Collection](#acquisition-and-evidence-collection)
- [Apple Guidance](#apple-guidance)
- [Attack Vectors and Adversary Techniques](#attack-vectors-and-adversary-techniques)
- [Blogs](#blogs)
- [Books and Magazines](#books-and-magazines)
- [Communities](#communities)
- [Hardware Information](#hardware-information)
- [Log Analysis](#log-analysis)
- [Malware](#malware)
- [Processes](#processes)
- [Persistence](#persistence)
- [Tools](#tools)
- [Trainings](#trainings)
- [Videos](#videos)

---

## Acquisition and Evidence Collection

- [Cellebrite Digital Collector (Former Macquisition)](https://cellebrite.com/en/digital-collector/) - Commercial Tooling for Acquisition of macOS Forensic Images.
- [mac_apt](https://github.com/ydkhatri/mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
- [Auditor](https://github.com/jipegit/OSXAuditor) - macOS DFIR tool.
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


## Books and Magazines

- [The Art of Mac Malware](https://taomm.org/) - Primer on malware on macOS by Patrick Wardle.
- [macOS Incident Response](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS) - macOS Incident Response primer (2017).
- [Kernel Book](http://newosxbook.com/index.php) - Book in three parts about the macOS Kernel.
- [macOS Internals](https://www.amazon.com/Mac-OS-Internals-Systems-Approach-ebook/dp/B004Y4UTLI/) - Internals of macOS (2007).
- [Kernel Programming](https://www.amazon.com/OS-X-iOS-Kernel-Programming/dp/1430235365/) - Kernel Programming reference for macOS / iOS.
- [eForensics Magazine](https://eforensicsmag.com/product/macos-forensics/) - Magazine for (macOS) Forensics.

## Communities

- [Cedric Owens](https://twitter.com/cedowens) - Twitter - macOS Security Researcher and Purple Teamer.
- [Csaba Fitzl](https://twitter.com/theevilbit) - Twitter - Hungarian Researcher specialized on macOS Security.
- [Patrick Wardle](https://twitter.com/patrickwardle) - Twitter - Founder of Objective-see, and Security Researcher.
- [Sarah Edwards](https://twitter.com/iamevltwin) - Twitter - Security Researcher and Trainer of SANS 518 Course.


## Hardware Information

- [Hardware Database](https://everymac.com/) - Lookup hardware specifications of every mac model.
- [M1 Chip Safe Mode](https://eclecticlight.co/2022/01/17/what-does-safe-mode-do-to-an-m1-mac/) - Blogpost on M1 Chipset Safe Mode.

## Log Analysis

- [Unified Log](https://eclecticlight.co/2018/03/20/macos-unified-log-2-content-and-extraction/) - A primer on macOS Unified Log.
- [Unified Log in Incident Response](https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response/) - Using the Unified Log for Incident Response.

## Malware

- [The Safe Mac](https://www.thesafemac.com/mmg-catalog/) - Older macOS Malware Catalogue.
- [VX-Underground](https://www.vx-underground.org/archive/VxHeaven/vl.php.html) - Malware Collection (various OS).
- [VX-Underground Malware Source Code](https://github.com/vxunderground/MalwareSourceCode) - Malware Sourcecode collection (various OS).

## Processes

- [True Tree](https://themittenmac.com/the-truetree-concept/) - Improved process tree.
- [Process and File Monitor](https://objective-see.com/products/utilities.html) - Command Line Utilit(ies) to monitor processes and files.

## Persistence

- [Persistence Samples](https://theevilbit.github.io/categories/persistence/) - Collection of persistence methods and samples used.
- [Knockknock](https://objective-see.com/products/knockknock.html) - Displays persistence items in macOS.

## Tools

- [Process Tree](https://github.com/ydkhatri/mac_apt/tree/729630c8bbe7a73cce3ca330305d3301a919cb07) - Process tree Repository.
- [FS Event Parser](https://github.com/dlcowen/FSEventsParser) - Parsing filesystem events.

## Trainings

- [Sumuri](https://sumuri.com/mac-training/) - Forensics Training in two parts for macOS, to gain Certified Forensic Mac Examiner Certification.
- [SANS 518](https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/) - Course at SANS for macOS and iOS Forensics.
- [Objective-by-the-sea](https://objectivebythesea.org/v5/index.html) - Security Conference (macOS) organized by Patrick Wardle.

## Videos

- [Curated YT Playlist](https://www.youtube.com/playlist?list=PL-zBXVr8oElPpEuhuTON7qE4k6iVh0zMv) - Playlist with macOS/iOS Security Topics.
