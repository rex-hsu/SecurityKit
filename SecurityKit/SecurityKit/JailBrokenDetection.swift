//
//  JailBrokenDetection.swift
//  SecurityKit
//
//  Created by Mehran on 4/3/1401 AP.
//

import Foundation
import UIKit

internal class JailBreakDetection {
    
    internal static func isJailBroken() -> Bool {
        let isCydiaInstalled = hasCydiaInstalled()
        let fileCheck = isPathsExist()
        let directories = isDirectoriesWriteable()
        let suspiciousApps = isContainsSuspiciousApps()
        
        return isCydiaInstalled ||
        fileCheck ||
        directories ||
        suspiciousApps ? true : false
    }
    
    //check if cydia is installed (using URI Scheme)
    static func hasCydiaInstalled() -> Bool {
        return UIApplication.shared.canOpenURL(URL(string: "cydia://")!)
    }
    
    //suspicious system and app paths to check
    private static var suspicousAppandSystemPaths: [String] {
        return [
            // Traditional jailbreaks
            "/usr/sbin/frida-server",
            "/etc/apt/sources.list.d/electra.list",
            "/etc/apt/sources.list.d/sileo.sources",
            "/.bootstrapped_electra",
            "/usr/lib/libjailbreak.dylib",
            "/jb/lzma",
            "/.cydia_no_stash",
            "/.installed_unc0ver",
            "/jb/offsets.plist",
            "/usr/share/jailbreak/injectme.plist",
            "/etc/apt/undecimus/undecimus.list",
            "/var/lib/dpkg/info/mobilesubstrate.md5sums",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/jb/jailbreakd.plist",
            "/jb/amfid_payload.dylib",
            "/jb/libjailbreak.dylib",
            "/usr/libexec/cydia/firmware.sh",
            "/var/lib/cydia",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/Users/",
            "/var/log/apt",
            "/Applications/Cydia.app",
            "/private/var/stash",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/cache/apt/",
            "/private/var/log/syslog",
            "/private/var/tmp/cydia.log",
            "/Applications/Icy.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/blackra1n.app",
            "/Applications/SBSettings.app",
            "/Applications/FakeCarrier.app",
            "/Applications/WinterBoard.app",
            "/Applications/IntelliScreen.app",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            
            // Traditional paths
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/bin/bash",

            // Modern jailbreak paths
            "/var/jb", // Rootless jailbreak root
            "/var/binpack", // Checkm8 jailbreak
            "/var/containers/Bundle/tweaksupport",
            "/var/mobile/Library/palera1n",
            "/var/mobile/Library/xyz.willy.Zebra",
            "/var/lib/undecimus",
            
            // Palera1n specific
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/etc",
            "/var/jb/Library",
            "/var/jb/.installed_palera1n",
            "/var/binpack/Applications",
            "/var/binpack/usr",
            
            // TrollStore
            "/var/containers/Bundle/Application/trollstorehelper",
            "/var/containers/Bundle/trollstore",
            
            // Bootstrap files
            "/var/jb/preboot",
            "/var/jb/var"
        ]
    }
    
    private static func isPathsExist() -> Bool {
        for path in suspicousAppandSystemPaths {
            if FileManager.default.fileExists(atPath: path){
                return true
            }
        }
        return false
    }
    
    private static var directories: [String] {
        return [
            "/",
            "/root/",
            "/private/",
            "/jb/"
        ]
    }
    
    private static func isDirectoriesWriteable() -> Bool {
        // Checks if the restricted directories are writeable.
        for path in directories {
            do{
                let filePath = path + UUID().uuidString
                try "i escaped the Jail".write(toFile: filePath, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: filePath)
                return true
            }catch let error{print(error.localizedDescription)}
        }
        return false
    }
    
    //suspicious apps path to check
    private static var suspiciousAppsPathToCheck: [String] {
        return [
                // Traditional jailbreak
                "/Applications/Cydia.app",
                "/Applications/blackra1n.app",
                "/Applications/FakeCarrier.app",
                "/Applications/Icy.app",
                "/Applications/IntelliScreen.app",
                "/Applications/MxTube.app",
                "/Applications/RockApp.app",
                "/Applications/SBSettings.app",
                "/Applications/WinterBoard.app",
                
                // Modern jailbreaks
                "/Applications/Palera1n.app",
                "/Applications/Sileo.app",
                "/Applications/Zebra.app",
                "/Applications/TrollStore.app",
                "/var/containers/Bundle/Application/TrollStore.app",
                
                // Checkra1n
                "/Applications/checkra1n.app",
                
                // Rootless jailbreak paths
                "/var/jb/Applications/Cydia.app",
                "/var/jb/Applications/Sileo.app",
                "/var/jb/Applications/Zebra.app"
        ]
    }
    
    //Check if suspicious apps (Cydia, FakeCarrier, Icy etc.) is installed
    private static func isContainsSuspiciousApps() -> Bool {
        for path in suspiciousAppsPathToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
}
