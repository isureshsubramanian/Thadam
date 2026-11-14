// ThadamNet host app (ADR-007 Decision 1): installs, enables, removes and reports on the
// content filter extension. No UI beyond that. Run from Terminal:
//   /Applications/ThadamNet.app/Contents/MacOS/ThadamNet [activate|deactivate|status]
// The app must be in /Applications. The first activation needs approval in System Settings.

import AppKit
import NetworkExtension
import SystemExtensions

private let filterID = "com.nerttiyana.thadam.net.filter"

enum Command: String {
    case activate, deactivate, status
}

@MainActor
final class Controller: NSObject, OSSystemExtensionRequestDelegate {
    private let command: Command

    init(_ command: Command) {
        self.command = command
    }

    func start() {
        switch command {
        case .activate:
            submit(.activationRequest(forExtensionWithIdentifier: filterID, queue: .main))
        case .deactivate:
            Task {
                await removeFilterConfiguration()
                submit(.deactivationRequest(forExtensionWithIdentifier: filterID, queue: .main))
            }
        case .status:
            Task {
                await printStatus()
                exit(0)
            }
        }
    }

    private func submit(_ request: OSSystemExtensionRequest) {
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        print("\(command.rawValue): request submitted")
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("approve it in System Settings > General > Login Items & Extensions > Network Extensions")
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        let needsReboot = result == .willCompleteAfterReboot
        Task { @MainActor in
            if needsReboot { print("completes after a restart") }
            if command == .activate {
                await enableFilterConfiguration()
            } else {
                print("extension removed")
            }
            exit(0)
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("request failed: \(error.localizedDescription)")
        exit(1)
    }

    private func enableFilterConfiguration() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true
            configuration.filterPackets = false
            manager.providerConfiguration = configuration
            manager.localizedDescription = "Thadam"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            print("filter enabled")
        } catch {
            print("enabling the filter failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private func removeFilterConfiguration() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            try await manager.removeFromPreferences()
            print("filter configuration removed")
        } catch {
            print("no filter configuration removed: \(error.localizedDescription)")
        }
    }

    private func printStatus() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let configured = manager.providerConfiguration != nil
            print("filter configured: \(configured ? "yes" : "no"), enabled: \(manager.isEnabled ? "yes" : "no")")
        } catch {
            print("status unavailable: \(error.localizedDescription)")
        }
    }
}

let arguments = CommandLine.arguments.dropFirst()
guard arguments.count <= 1, let command = Command(rawValue: arguments.first ?? "activate") else {
    print("usage: ThadamNet [activate|deactivate|status]")
    exit(2)
}
let controller = Controller(command)
controller.start()
NSApplication.shared.setActivationPolicy(.accessory)
NSApplication.shared.run()
