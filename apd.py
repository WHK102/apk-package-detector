#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import os
import zipfile
import json
import re


class MainCls(object):


    def __init__(self):

        # Results DTO Model
        self.results = {
            'status': {
                'success' : False,
                'errors'  : {
                    'target-is-empty'     : False,
                    'target-is-not-found' : False,
                    'target-is-not-zip'   : False,
                    'target-is-not-jar'   : False,
                    'target-is-not-apk'   : False,
                }
            },
            'result': {
                'sub-frameworks': {
                    'cordova'      : False,
                    'appcelerator' : False
                },
                'protections': {
                    'appcelerator-obfuscation'    : False,
                    'okhttp3-certificate-pinning' : False,
                    'root-detector'               : False
                    # 'reflection'                 : False,
                    # 'proguard'                   : False,
                    # 'string-encription'          : False,
                    # 'class-encription'           : False,
                    # 'tamper-detector'            : False,
                    # 'debug-detector'             : False,
                    # 'emulator-detector'          : False
                }
            }
        }

        # The zip file lists
        # More memory but is more fast to multiple processing
        zipFiles = []

        # Parse CLI arguments
        argparseHandler = argparse.ArgumentParser(add_help=False)

        argparseHandler.add_argument(
            '-h',
            '--help',
            dest='help',
            action='store_true'
        )

        argparseHandler.add_argument(
            '-o',
            '--out-format',
            dest='printFormat',
            nargs='+'
        )

        # Parse the arguments values from sys
        argparseParsed, argparseExtras = argparseHandler.parse_known_args(
            sys.argv[1:]
        )

        # The print format
        self.printFormat = (
            argparseParsed.printFormat[0] if (
                (argparseParsed.printFormat is not None) and
                (len(argparseParsed.printFormat) > 0)
            ) else 'human'
        )

        # Have arguments?
        if((len(sys.argv) < 2) or (argparseParsed.help)):
            return self.printHumanHelp()

        # Have filename?
        if(len(argparseExtras) == 0):
            self.results['status']['errors']['target-is-empty'] = True
            return self.printResults()

        # The target file path
        self.targetPath = argparseExtras[0]

        # Target file exists?
        self.checkFileExists()

        # Is a valid ZIP file?
        self.checkFileIsZip()

        # Extract all filenames from the zip file
        self.extractFileNames()

        # Is a valid JAR file?
        self.checkFileIsJar()

        # Is a valid APK file?
        self.checkFileIsApk()

        # Extract all package names
        self.extractPackageNames()

        # Technology detection
        self.checkFileIsCordova()
        self.checkFileIsAppcelerator()

        # Security detection
        self.checkContainsRootDetector()
        self.checkContainsCertPinning()

        # Print the final results
        self.printResults(0)


    def checkFileExists(self):

        if(not os.path.isfile(self.targetPath)):
            self.results['status']['errors']['target-is-not-found'] = True
            self.printResults(1)


    def checkFileIsZip(self):

        if(not zipfile.is_zipfile(self.targetPath)):
            self.results['status']['errors']['target-is-not-zip'] = True
            self.printResults(2)


    def extractFileNames(self):
        
        zf = zipfile.ZipFile(self.targetPath, 'r')
        self.zipFiles = zf.namelist()
        zf.close()


    def checkFileIsJar(self):

        # Manifest exists?        
        if(not 'META-INF/MANIFEST.MF' in self.zipFiles):
            self.results['status']['errors']['target-is-not-jar'] = True
            self.printResults(3)

        # Is a valid manifest?
        manifestContent = self.readContent('META-INF/MANIFEST.MF')
        if(not re.match(r'Manifest\-Version:\s+\d{1}\.\d{1,2}', manifestContent.splitlines()[0])):
            self.results['status']['errors']['target-is-not-jar'] = True
            self.printResults(3)


    def checkFileIsApk(self):

        for fileToFind in ['classes.dex', 'AndroidManifest.xml']:
            if(not fileToFind in self.zipFiles):
    
                self.results['status']['errors']['target-is-not-apk'] = True
                self.printResults(4)


    def checkFileIsCordova(self):

        # Check by package name
        if(self.packageExists('org.apache.cordova')):

            # Files required by cordova compiles project
            for fileToFind in [
                'assets/www/cordova.js',
                'assets/www/cordova_plugins.js',
                'assets/www/cordova-js-src'
            ]:
                if(fileToFind in self.zipFiles):
                    self.results['result']['sub-frameworks']['cordova'] = True


    def checkFileIsAppcelerator(self):

        if(
            self.packageExists('appcelerator') or
            self.packageExists('org.appcelerator')
        ):
            self.results['result']['sub-frameworks']['appcelerator'] = True
            self.results['result']['protections']['appcelerator-obfuscation'] = True

    
    def checkContainsCertPinning(self):

        # OkHttp3 support
        if(not self.packageExists('okhttp3')):
            return

        # Find dex files
        for fileName in self.zipFiles:

            # The filename is a .dex?
            if(re.match(r'^classes\d*\.dex$', fileName)):
        
                # Load classes container
                dexBinary = self.readContent(fileName, binaryMode=True)

                # Have a certificate fingerprint format?
                certs = re.findall(br'sha\d+\/[a-zA-Z0-9\+=\/]+', dexBinary)
                if(len(certs) > 0):
                    self.results['result']['protections']['okhttp3-certificate-pinning'] = True

                    break


    def checkContainsRootDetector(self):

        # Find dex files
        for fileName in self.zipFiles:

            # The filename is a .dex?
            if(re.match(r'^classes\d*\.dex$', fileName)):

                # Load classes container
                dexBinary = self.readContent(fileName, binaryMode=True)

                for fingerprint in [
                    '/data/local/bin/su',
                    '/data/local/xbin/su',
                    '/sbin/su',
                    '/su/bin/',
                    '/system/bin/su',
                    '/system/bin/.ext/su',
                    '/system/bin/failsafe/',
                    '/system/sd/xbin/su',
                    '/system/usr/we-need-root/',
                    '/system/xbin/su',
                    '/system/app/Superuser.apk',
                    'rootcloak',
                    'rootcloakplus',
                    'superuser',
                    'supersu'
                ]:
                    dettections = re.findall(
                        re.escape(fingerprint).encode(),
                        dexBinary,
                        flags=re.IGNORECASE
                    )
                    if(len(dettections) > 0):
                        self.results['result']['protections']['root-detector'] = True
                        break

                if(self.results['result']['protections']['root-detector']):
                    break


    def readContent(self, path, binaryMode=False):

        zf = zipfile.ZipFile(self.targetPath, 'r')
        data = zf.read(path)
        zf.close()

        return (data if binaryMode else data.decode(encoding='UTF-8', errors='ignore'))


    def extractPackageNames(self):

        # Reset values
        self.packages = []

        # Find dex files
        for fileName in self.zipFiles:

            # The filename is a .dex?
            if(re.match(r'^classes\d*\.dex$', fileName)):

                # Load classes container
                dexBinary = self.readContent(fileName, binaryMode=True)

                # Lcom/google/firebase/components/ComponentDiscovery;
                packages = re.findall(br'\[L[a-zA-Z0-9\-_\/\$]+?;', dexBinary)

                # Parse each string
                if(packages):
                    for package in packages:
                        package = package[2:][:-1].replace(b'/', b'.')
                        if(b'$' in package):
                            package = package.split(b'$')[0]
                        self.packages.append(package.decode(encoding='UTF-8'))

        # Unique values
        self.packages = list(set(self.packages))

        # Sorted values
        self.packages.sort()


    def packageExists(self, package):

        for packageTocheck in self.packages:
            if(packageTocheck.startswith(package)):
                return True

        return False


    def printHumanHelp(self):

        self.printHumanHeader()
        print('\n'.join([
            'Get extended info from APK file.',
            'Use      : ' + sys.argv[0] + ' [options] [APK target file]',
            'Options  :',
            '  -h, --help         Print the help message.',
            '  -o, --out-format   Out format: human, json',
            'Examples :',
            '  ' + sys.argv[0] + ' test.apk',
            '  ' + sys.argv[0] + ' -o json test.apk'
        ]))


    def printHumanHeader(self):

        print('~ APK Package Detector v0.1.1-b - whk@elhacker.net ~')


    def printResults(self, exitStatus=0):
        
        # The success status is injected
        if(exitStatus == 0):
            self.results['status']['success'] = True

        if(self.printFormat == 'json'):
            print(json.dumps(self.results, indent=4))

        else: # Human format

            self.printHumanHeader()

            if(not self.results['status']['success']):

                if(self.results['status']['errors']['target-is-empty']):
                    print('! The target file is required.')
                    self.printHumanHelp()

                elif(self.results['status']['errors']['target-is-not-found']):
                    print('! The target file is not found: ' + self.targetPath)

                elif(self.results['status']['errors']['target-is-not-zip']):
                    print('! The target file is not a zip file.')

                elif(self.results['status']['errors']['target-is-not-jar']):
                    print('! The target file is not a jar file.')

                elif(self.results['status']['errors']['target-is-not-apk']):
                    print('! The target file is not a apk file.')

                else:
                    print('! Unknown error ¯\\_(ツ)_/¯')

            else:

                if(self.results['result']['sub-frameworks']['cordova']):
                    print('+ Framework used: Aache Cordova. https://cordova.apache.org/')

                elif(self.results['result']['sub-frameworks']['appcelerator']):
                    print('+ Framework used: Appcelerartor. https://www.appcelerator.com/')

                else:
                    print('+ Framework used: Native or unknown Framework.')

                print('\n'.join([
                    '+ Protection systems :',
                    '  - Appcelerator Assets Obfuscation   : ' + ('Yes' if self.results['result']['protections']['appcelerator-obfuscation'] else 'No'),
                    '  - OkHttp3 Certificate Pinning       : ' + ('Yes' if self.results['result']['protections']['okhttp3-certificate-pinning'] else 'No'),
                    '  - Root and Virtual Machine detector : ' + ('Yes' if self.results['result']['protections']['root-detector'] else 'No')
                ]))
            
                haveProtectionSystem = False
                for value in self.results['result']['protections'].values():
                    if(value):
                        haveProtectionSystem = True
                        break

                if(not haveProtectionSystem):
                    print('  We have not found any protection system ¯\\_(ツ)_/¯')

        exit(exitStatus)


if __name__ == '__main__':

    try:
        mainCls = MainCls()

    except KeyboardInterrupt as e:
        # Ctrl+C, it's ok.
        pass

    except Exception as e:
        # Unhandled exception
        raise e
