# APK Package Detector

[![Chileno](https://img.shields.io/badge/From-Chile-blue.svg)](https://es.wikipedia.org/wiki/Chile)
[![Licencia](https://img.shields.io/badge/license-GPL%20(%3E%3D%202)-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Contribuciones](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/WHK102/apk-package-detector/issues)
[![Donaciones](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/whk102)

APK Package Detector is a tool for **pentesters**, get the most common
compilation and security properties of different types of files.

*It does not require installing Java, SDK, external applications or packages with
additional binaries.*


## Requirements

- Python 3


## Use

Example of execution:

```bash
$ python3 apd.py
~ APK Package Detector v0.1.1-b - whk@elhacker.net ~
Get extended info from APK file.
Use      : apd.py [options] [APK target file]
Options  :
  -h, --help         Print the help message.
  -o, --out-format   Out format: human, json
Examples :
  apd.py test.apk
  apd.py -o json test.apk

$ python3 apd.py test/pinning.apk 
~ APK Package Detector v0.1.1-b - whk@elhacker.net ~
+ Framework used: Native or unknown Framework.
+ Protection systems :
  - Appcelerator Assets Obfuscation   : No
  - OkHttp3 Certificate Pinning       : Yes
  - Root and Virtual Machine detector : Yes
```


## Binaries supported

- Android APK


## Frameworks supported to detection

- Appcelerator
- Apache Cordova