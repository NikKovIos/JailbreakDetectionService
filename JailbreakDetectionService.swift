// Created by @NikeKov  

struct JailbreakCheckResult {
    /// true - was Jailbroken
    let isJailbreaked: Bool

    /// If Jailbroken - what was the reason
    let jailbreakedReason: String?
}

protocol JailbreakDetectionService {
    func checkJailbreak() -> JailbreakCheckResult
}

/// Jailbreak detection service.
/// Important: The implementation assumes that the service would be initialized as one instance per app. 
/// In order to jailbreakResultCache work. You can make multiple instances, but in that case the detection would be every time from scratch.
/// Service can do falsepositive results.
final class JailbreakDetectionServiceImplementation {
    /// In order to make detection only one time per app lifetime
    private var jailbreakResultCache: JailbreakCheckResult?
}

// MARK: - Service Logic

extension JailbreakDetectionServiceImplementation: JailbreakDetectionService {
    func checkJailbreak() -> JailbreakCheckResult {
#if targetEnvironment(simulator)
        return JailbreakCheckResult(isJailbreaked: false, jailbreakedReason: nil)
#endif

        if let jailbreakResultCache = self.jailbreakResultCache {
            return jailbreakResultCache
        }

        let jailbreakFilePaths = [
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
            "/private/var/stash",
            "/private/var/lib/cydia",
            "/private/var/cache/apt/",
            "/private/var/log/syslog",
            "/private/var/tmp/cydia.log",
            "/Applications/RockApp.app",
            "/Applications/blackra1n.app",
            "/Applications/Cydia.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
        ]
        for path in jailbreakFilePaths {
            if FileManager.default.fileExists(atPath: path) {
                return saved(JailbreakCheckResult(isJailbreaked: true, jailbreakedReason: "path exists: \(path)"))
            }
        }

        if let cydiaURL = URL(string: "cydia://package/com.example.package") {
            if UIApplication.shared.canOpenURL(cydiaURL) {
                return saved(JailbreakCheckResult(isJailbreaked: true, jailbreakedReason: "can open cydiaURL"))
            }
        }

        let jailbreakBinaryNames = [
            "ssh",
            "sshd",
            "dropbear",
            "sftp-server"
        ]
        for name in jailbreakBinaryNames {
            let path = "/bin/\(name)"
            if FileManager.default.fileExists(atPath: path) {
                return saved(JailbreakCheckResult(isJailbreaked: true, jailbreakedReason: "file exists: \(path)"))
            }
        }

        let systemDirectories = [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/libexec"
        ]
        for directory in systemDirectories {
            if FileManager.default.isWritableFile(atPath: directory) {
                let result = JailbreakCheckResult(isJailbreaked: true, jailbreakedReason: "system dir writable: \(directory)")
                jailbreakResultCache = result
                return result
            }
        }

        return saved(JailbreakCheckResult(isJailbreaked: false, jailbreakedReason: nil))
    }

    private func saved(_ result: JailbreakCheckResult) -> JailbreakCheckResult {
        self.jailbreakResultCache = result
        return result
    }
}
