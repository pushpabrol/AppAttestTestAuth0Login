import SwiftUI
import DeviceCheck
import CryptoKit
import AuthenticationServices
import SimpleKeychain

struct ContentView: View {
    @StateObject var viewModel = AppAttestViewModel()
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    
                        if let keyIdentifier = viewModel.keyIdentifier {
                            keyIdentifierSection(keyIdentifier: keyIdentifier)
                        }
                    else {
                        ProgressView()
                    }
                        if viewModel.isUserLoggedIn {
                            loggedInView()
                        } else {
                            if viewModel.appAttested {
                                Text("App Attested! ready to login!")
                                    .padding()
                                    .border(Color.gray, width: 1)
                                    .cornerRadius(8)
                                    
                                Button("Login") {
                                    Task {
                                        await viewModel.startPKCEFlow()
                                    }
                                }.buttonStyle(PrimaryButtonStyle())
                            }
                            else {
                                ProgressView()
                            }
                        }
                    
                }
                .padding()
                .navigationTitle("App Attest Example")
            }
            .alert(isPresented: $viewModel.showAlert) {
                Alert(title: Text("Status"), message: Text(viewModel.alertMessage), dismissButton: .default(Text("OK")))
            }
            .onAppear {
                viewModel.initializeAttestationKey()
                
                
            }
        }
    }

    private func keyIdentifierSection(keyIdentifier: String) -> some View {
        Section(header: Text("Key Identifier")) {
            Text(keyIdentifier)
                .padding()
                .border(Color.gray, width: 1)
                .cornerRadius(8)
           
        }
    }

    private func loggedInView() -> some View {
        VStack {
            Text("User is logged in")
            Text("Token: \(viewModel.tokenData)")
            Button("Logout") {
                viewModel.logout()
            }
            .buttonStyle(PrimaryButtonStyle())
        }
    }
}

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Self.Configuration) -> some View {
        configuration.label
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(8)
    }
}


class AppAttestViewModel: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    @Published var isLoading = false
    @Published var showAlert = false
    @Published var alertMessage = ""
    @Published var keyIdentifier: String?
    @Published var isUserLoggedIn = false
    @Published var attestationChallenge: String?
    @Published var tokenData = ""
    @Published var appAttested = false

    private let keychain = SimpleKeychain()
    private let verifiedAttestationKey = "verifiedAttestation"
    private let userSessionKey = "userSession"
    
    func logout() {
            isUserLoggedIn = false
            tokenData = ""
        try! keychain.deleteItem(forKey: userSessionKey) // Clearing token from the keychain
        }
    
    override init() {
        super.init()
        keyIdentifier = UserDefaults.standard.string(forKey: "appAttestKeyId")
        initializeAttestationKey()
    }

    func loadConfigValue(forKey key: String) -> String {
        guard let path = Bundle.main.path(forResource: "Config", ofType: "plist"),
              let dict = NSDictionary(contentsOfFile: path) as? [String: AnyObject],
              let value = dict[key] as? String else {
            fatalError("Missing or invalid key in Config.plist")
        }
        return value
    }

    func initializeAttestationKey() {
        if let _ = keyIdentifier, let verified = try? keychain.string(forKey: verifiedAttestationKey), verified == "true" {
            // Key exists and attestation is verified, no need to do anything.
            DispatchQueue.main.async {
                self.appAttested = true
            }
            return
        }
        
        Task {
            await generateAttestationKey()
            await requestAttestationChallenge()
            await verifyAttestation()
        }
    }
    
     

    func generateAttestationKey() async {
        isLoading = true
        await withCheckedContinuation { continuation in
            DCAppAttestService.shared.generateKey { [weak self] result, error in
                DispatchQueue.main.async {
                    self?.isLoading = false
                    if let error = error {
                        self?.handleError(error)
                        continuation.resume()
                        return
                    }
                    if let keyId = result {
                        self?.keyIdentifier = keyId
                        UserDefaults.standard.set(keyId, forKey: "appAttestKeyId")
                    }
                    continuation.resume()
                }
            }
        }
    }

    func handleError(_ error: Error) {
        if let error = error as NSError? {
            switch error.code {
            case 1:
                alertMessage = "Device is not eligible."
            case 2:
                alertMessage = "Data not available."
            case 3:
                alertMessage = "Transient error. Try again."
            default:
                alertMessage = "Unknown error: \(error.localizedDescription)"
            }
        } else {
            alertMessage = error.localizedDescription
        }
        showAlert = true
    }

    func startPKCEFlow() async {
        
        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(codeVerifier: codeVerifier)

        if let assertionData = await createAssertion() {
            let (assertionChallenge, clientData, assertion) = assertionData
            await initiateAuthorizationRequest(codeVerifier: codeVerifier, codeChallenge: codeChallenge, clientData: clientData, keyId: keyIdentifier!, assertion: assertion)
        }
    }

    func requestAttestationChallenge() async {
        let urlString = loadConfigValue(forKey: "AttestationChallengeURL")
        guard let url = URL(string: urlString) else { return }

        await withCheckedContinuation { continuation in
            let task = URLSession.shared.dataTask(with: url) { data, _, error in
                DispatchQueue.main.async {
                    if let error = error {
                        self.handleError(error)
                    } else if let data = data {
                        do {
                            struct Response: Codable {
                                var attestationChallenge: String
                            }
                            let jsonResponse = try JSONDecoder().decode(Response.self, from: data)
                            self.attestationChallenge = jsonResponse.attestationChallenge
                        } catch {
                            self.handleError(error)
                        }
                    }
                    continuation.resume()
                }
            }
            task.resume()
        }
    }
    
    func urlSafeBase64Encode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func verifyAttestation() async {
        guard let keyIdentifier = keyIdentifier, let attestationChallenge = attestationChallenge else {
            DispatchQueue.main.async {
                self.alertMessage = "Key identifier or attestation challenge is not available."
                self.showAlert = true
            }
            return
        }

        let clientData = attestationChallenge.data(using: .utf8)!
        let clientDataHash = SHA256.hash(data: clientData)
        let clientDataHashData = Data(clientDataHash)

        DispatchQueue.main.async {
            self.isLoading = true
        }

        let attestationObject: Data? = await withCheckedContinuation { continuation in
            DCAppAttestService.shared.attestKey(keyIdentifier, clientDataHash: clientDataHashData) { attestationObject, error in
                DispatchQueue.main.async {
                    self.isLoading = false
                    if let error = error {
                        self.handleError(error)
                        continuation.resume(returning: nil)
                    } else {
                        continuation.resume(returning: attestationObject)
                    }
                }
            }
        }

        guard let attestationObject = attestationObject else { return }

        let verifyUrlString = loadConfigValue(forKey: "VerifyAttestationURL")
        guard let verifyUrl = URL(string: verifyUrlString) else { return }

        var request = URLRequest(url: verifyUrl)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: String] = [
            "attestationObject": attestationObject.base64EncodedString(),
            "keyId": keyIdentifier,
            "attestationChallenge": attestationChallenge
        ]

        guard let httpBody = try? JSONSerialization.data(withJSONObject: body) else { return }

        request.httpBody = httpBody

        await withCheckedContinuation { continuation in
            let task = URLSession.shared.dataTask(with: request) { data, _, error in
                DispatchQueue.main.async {
                    if let error = error {
                        self.handleError(error)
                    } else if let data = data {
                        do {
                            let jsonResponse = try JSONSerialization.jsonObject(with: data, options: [])
                            UserDefaults.standard.set(jsonResponse, forKey: "verificationResponse")
                            self.appAttested = true
                            try? self.keychain.set("true", forKey: self.verifiedAttestationKey)
                        } catch {
                            self.handleError(error)
                        }
                    }
                    continuation.resume()
                }
            }
            task.resume()
        }
    }

    func initiateAuthorizationRequest(codeVerifier: String, codeChallenge: String, clientData: Data, keyId: String, assertion: Data) async {
        let clientId = loadConfigValue(forKey: "CLIENT_ID")
        let redirectUri = loadConfigValue(forKey: "REDIRECT_URI")
        let authEndpoint = loadConfigValue(forKey: "AUTH_ENDPOINT")

        guard let redirectUriScheme = URL(string: redirectUri)?.scheme else {
            alertMessage = "Invalid redirect URI"
            showAlert = true
            return
        }
        
        if let keyIdData = keyIdentifier?.data(using: .utf8) {
            let urlSafeKeyId = urlSafeBase64Encode(keyIdData)
            let urlSafeClientData = urlSafeBase64Encode(clientData)
            let urlSafeAssertion = urlSafeBase64Encode(assertion)
            
            
            var urlComponents = URLComponents(string: authEndpoint)!
            urlComponents.queryItems = [
                URLQueryItem(name: "client_id", value: clientId),
                URLQueryItem(name: "redirect_uri", value: redirectUri),
                URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "scope", value: "openid profile email"),
                URLQueryItem(name: "code_challenge_method", value: "S256"),
                URLQueryItem(name: "code_challenge", value: codeChallenge),
                URLQueryItem(name: "clientData", value: urlSafeClientData),
                URLQueryItem(name: "keyId", value: urlSafeKeyId),
                URLQueryItem(name: "assertion", value: urlSafeAssertion)
            ]
            
            let authURL = urlComponents.url!
            
            DispatchQueue.main.async {
                let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: redirectUriScheme) { callbackURL, error in
                    if let error = error {
                        self.alertMessage = "Authorization failed: \(error.localizedDescription)"
                        self.showAlert = true
                        return
                    }
                    
                    guard let callbackURL = callbackURL else {
                        self.alertMessage = "No callback URL"
                        self.showAlert = true
                        return
                    }
                    
                    let queryItems = URLComponents(string: callbackURL.absoluteString)?.queryItems
                    let authorizationCode = queryItems?.first(where: { $0.name == "code" })?.value
                    
                    if let code = authorizationCode {
                        Task {
                            if let assertionData = await self.createAssertion() {
                                let (_, clientData, assertion) = assertionData
                                await self.exchangeCodeForToken(code: code, codeVerifier: codeVerifier, clientData: clientData, keyId: keyId, assertion: assertion)
                            }
                        }
                    }
                }
                session.presentationContextProvider = self
                session.start()
            }
        }
    }

    func exchangeCodeForToken(code: String, codeVerifier: String, clientData: Data, keyId: String, assertion: Data) async {
        let tokenEndpoint = loadConfigValue(forKey: "TOKEN_ENDPOINT")
        let clientId = loadConfigValue(forKey: "CLIENT_ID")
        let redirectUri = loadConfigValue(forKey: "REDIRECT_URI")

        var request = URLRequest(url: URL(string: tokenEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "grant_type": "authorization_code",
            "client_id": clientId,
            "code": code,
            "redirect_uri": redirectUri,
            "code_verifier": codeVerifier,
            "clientData": clientData.base64EncodedString(),
            "keyId": keyId,
            "assertion": assertion.base64EncodedString()
        ]

        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    self.alertMessage = "Token exchange failed: \(error.localizedDescription)"
                    self.showAlert = true
                    return
                }

                guard let data = data else {
                    self.alertMessage = "No data received"
                    self.showAlert = true
                    return
                }
                if let tokenResponse1 = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
                    print("Token response: \(tokenResponse1)")
                }
                
                if let tokenResponse = try? JSONDecoder().decode(TokenResponse.self, from: data) {
                    self.tokenData = "Access Token: \(tokenResponse.access_token)\nID Token: \(tokenResponse.id_token)"
                                    self.isUserLoggedIn = true
                                    try? self.keychain.set(tokenResponse.access_token, forKey: self.userSessionKey)
                                } else {
                                    self.alertMessage = "Failed to parse token response."
                                    self.showAlert = true
                                }
            }
        }.resume()
    }
    
    struct TokenResponse: Codable {
            let access_token: String
            let id_token: String
            let expires_in: Int
            let token_type: String
        }

    // PKCE Helper functions
    func generateCodeVerifier() -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        return String((0..<128).map { _ in characters.randomElement()! })
    }

    func generateCodeChallenge(codeVerifier: String) -> String {
        let data = Data(codeVerifier.utf8)
        let hashed = SHA256.hash(data: data)
        return Data(hashed).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func createAssertion() async -> (String, Data, Data)? {
        guard let keyIdentifier = keyIdentifier else {
            DispatchQueue.main.async {
                self.alertMessage = "Key identifier is not available."
                self.showAlert = true
            }
            return nil
        }

        guard let assertionChallenge = await requestAssertionChallenge() else {
            DispatchQueue.main.async {
                self.alertMessage = "Failed to fetch assertion challenge."
                self.showAlert = true
            }
            return nil
        }

        let assertionContent = ["userId": "User123", "client_id": "1234", "challenge": assertionChallenge] as [String: Any]
        guard let jsonData = try? JSONSerialization.data(withJSONObject: assertionContent) else {
            DispatchQueue.main.async {
                self.alertMessage = "Failed to encode assertion content."
                self.showAlert = true
            }
            return nil
        }

        let clientDataHash = SHA256.hash(data: jsonData)
        let clientDataHashData = Data(clientDataHash)

        return await withCheckedContinuation { continuation in
            DCAppAttestService.shared.generateAssertion(keyIdentifier, clientDataHash: clientDataHashData) { assertion, error in
                DispatchQueue.main.async {
                    if let error = error {
                        self.alertMessage = "Error generating assertion: \(error.localizedDescription)"
                        self.showAlert = true
                        continuation.resume(returning: nil)
                    } else if let assertion = assertion {
                        continuation.resume(returning: (assertionChallenge, jsonData, assertion))
                    } else {
                        continuation.resume(returning: nil)
                    }
                }
            }
        }
    }

    func requestAssertionChallenge() async -> String? {
        let urlString = loadConfigValue(forKey: "AssertionChallengeURL")
        guard let url = URL(string: urlString) else { return nil }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: String] = ["keyId": keyIdentifier!]
        guard let httpBody = try? JSONSerialization.data(withJSONObject: body) else { return nil }

        request.httpBody = httpBody

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            struct Response: Codable {
                var assertionChallenge: String
            }
            let jsonResponse = try JSONDecoder().decode(Response.self, from: data)
            return jsonResponse.assertionChallenge
        } catch {
            return nil
        }
    }

    // ASWebAuthenticationPresentationContextProviding conformance
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return UIApplication.shared.windows.first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}



