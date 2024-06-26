# App Attest, app assertion verification with auth0 endpoints 

This SwiftUI project demonstrates the implementation of Apple's App Attest feature alongside the Proof Key for Code Exchange (PKCE) flow to securely authenticate users. It involves device attestation and  assertion verification with auth0 endpoints via a proxy - for validating attestations and handling assertion checks for user authentication calls. this project assumes auth0 is behind a proxy with code in the proxy to handle attestation, assertion verification based on the attestation as well as using private key jwt for client authentication - example [Cloudflare proxy code](https://github.com/pushpabrol/cloudflare-worker-auth0-app-attest)

## Features

- **Apple App Attest**: Ensures the app's integrity and validates that the app has not been tampered with.
- **PKCE Flow**: Enhances OAuth 2.0 security by using a code verifier and code challenge.
- **SwiftUI Interface**: Provides a modern and user-friendly interface using SwiftUI.
- **Secure Storage**: Utilizes Keychain for secure storage of sensitive information.
- **Add assertions**: Adds assertions using app attest service for calls to /authorize and /oauth/token

## Requirements

- iOS 14.0+
- Xcode 12.0+
- Swift 5.3+

## Installation

1. **Clone the repository**:
2. **Open the project** in Xcode:
   ```bash
   open AppAttestExample.xcodeproj
   ```
3. **Build and run** the application on a compatible iOS device.

## Configuration

1. **Config.plist**: Ensure you have the following keys set in your `Config.plist` file:
   - `AttestationChallengeURL`
   - `VerifyAttestationURL`
   - `CLIENT_ID`
   - `REDIRECT_URI`
   - `AUTH_ENDPOINT`
   - `TOKEN_ENDPOINT`
   - `AssertionChallengeURL`

## Usage

1. **App Initialization**:
   - On launch, the app initializes the attestation key and checks if the device is attested.
   - If the attestation is successful, the app indicates readiness for login.

2. **User Login**:
   - The user can log in using the PKCE flow.
   - The login process involves creating a code verifier and code challenge, generating an assertion, and initiating an authorization request.

3. **Assumptions**:
   - This is a very targeted solution 
   - The user can log out, which clears the session data.

## Classes and Methods

### `AppAttestViewModel`

- **Properties**:
  - `@Published var isLoading`: Tracks the loading state.
  - `@Published var showAlert`: Controls the display of alerts.
  - `@Published var alertMessage`: Message displayed in alerts.
  - `@Published var keyIdentifier`: Stores the key identifier.
  - `@Published var isUserLoggedIn`: Tracks the user's login status.
  - `@Published var attestationChallenge`: Stores the attestation challenge.
  - `@Published var tokenData`: Stores the authentication token data.
  - `@Published var appAttested`: Indicates if the app is attested.

- **Methods**:
  - `func logout()`: Logs the user out.
  - `func loadConfigValue(forKey key: String) -> String`: Loads configuration values from `Config.plist`.
  - `func initializeAttestationKey()`: Initializes the attestation key.
  - `func generateAttestationKey() async`: Generates a new attestation key.
  - `func handleError(_ error: Error)`: Handles errors by displaying appropriate messages.
  - `func startPKCEFlow() async`: Initiates the PKCE flow.
  - `func requestAttestationChallenge() async`: Requests an attestation challenge from the server.
  - `func urlSafeBase64Encode(_ data: Data) -> String`: Encodes data in URL-safe base64.
  - `func verifyAttestation() async`: Verifies the attestation with the server.
  - `func initiateAuthorizationRequest(codeVerifier: String, codeChallenge: String, clientData: Data, keyId: String, assertion: Data) async`: Initiates an authorization request.
  - `func exchangeCodeForToken(code: String, codeVerifier: String, clientData: Data, keyId: String, assertion: Data) async`: Exchanges authorization code for tokens.
  - `func generateCodeVerifier() -> String`: Generates a PKCE code verifier.
  - `func generateCodeChallenge(codeVerifier: String) -> String`: Generates a PKCE code challenge.
  - `func createAssertion() async -> (String, Data, Data)?`: Creates an assertion for the attestation.
  - `func requestAssertionChallenge() async -> String?`: Requests an assertion challenge from the server.

### `ContentView`

- **Properties**:
  - `@StateObject var viewModel`: An instance of `AppAttestViewModel`.

- **Methods**:
  - `var body: some View`: The main view that displays the attestation status, login button, and user information.
  - `private func keyIdentifierSection(keyIdentifier: String) -> some View`: Displays the key identifier.
  - `private func loggedInView() -> some View`: Displays the user's login status and token information.

### `PrimaryButtonStyle`

A custom button style for consistent button appearance.

```swift
struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Self.Configuration) -> some View {
        configuration.label
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(8)
    }
}
```

## Security

This project uses several security measures:
- **App Attest**: Ensures the app's integrity.
- **Keychain**: Sensitive data like tokens are stored securely in the iOS Keychain.

