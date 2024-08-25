package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	clientID = "00000000441cc96b"
	scope    = "openid profile XboxLive.signin"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type RegistrationResponse struct {
	Username string
	Proof    int64
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type XboxLiveAuthRequest struct {
	Properties struct {
		AuthMethod string `json:"AuthMethod"`
		SiteName   string `json:"SiteName"`
		RpsTicket  string `json:"RpsTicket"`
	} `json:"Properties"`
	RelyingParty string `json:"RelyingParty"`
	TokenType    string `json:"TokenType"`
}

type XboxLiveAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		Xui []struct {
			Uhs string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

type XSTSAuthRequest struct {
	Properties struct {
		SandboxId  string   `json:"SandboxId"`
		UserTokens []string `json:"UserTokens"`
	} `json:"Properties"`
	RelyingParty string `json:"RelyingParty"`
	TokenType    string `json:"TokenType"`
}

type XSTSAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		Xui []struct {
			Uhs string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

type MinecraftAuthResponse struct {
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   int      `json:"expires_in"`
}

type Entitlement struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

type GameOwnershipResponse struct {
	Items []struct {
		Name      string `json:"name"`
		Signature string `json:"signature"`
	} `json:"items"`
	Signature string `json:"signature"`
	KeyId     string `json:"keyId"`
}

var (
	deviceCode *DeviceCodeResponse
	mutex      sync.Mutex
)

func getDeviceCode() (*DeviceCodeResponse, error) {
	form := url.Values{}
	form.Add("scope", scope)
	form.Add("client_id", clientID)
	form.Add("response_type", "device_code")

	resp, err := http.Post("https://login.live.com/oauth20_connect.srf", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var deviceCodeResponse DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCodeResponse); err != nil {
		return nil, err
	}
	return &deviceCodeResponse, nil
}

func getAuthToken(deviceCode *DeviceCodeResponse) (*AccessTokenResponse, error) {
	tokenURL := fmt.Sprintf("https://login.live.com/oauth20_token.srf?client_id=%s", clientID)

	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("device_code", deviceCode.DeviceCode)
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	expirationTime := time.Now().Add(time.Second * time.Duration(deviceCode.ExpiresIn))
	// log.Printf("Polling for token. Expiration time is: %s", expirationTime.Format(time.RFC3339))

	i := 0
	for time.Now().Before(expirationTime) {
		if i > 6 {
			return nil, fmt.Errorf("timeout while polling for authentication")
		}
		resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			log.Printf("Request failed: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var tokenResponse AccessTokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
				log.Printf("Failed to decode response: %v", err)
				continue
			}
			log.Println("Token successfully obtained")
			return &tokenResponse, nil
		} else {
			// log.Printf("Polling failed with status: %d. Retrying in %d seconds...", resp.StatusCode, deviceCode.Interval)
			i++
		}

		time.Sleep(time.Second * time.Duration(deviceCode.Interval))
	}

	log.Println("Device code expired or polling timed out.")
	return nil, fmt.Errorf("timeout while polling for authentication")
}

func authenticateWithXboxLive(accessToken string) (*XboxLiveAuthResponse, error) {
	xboxAuthURL := "https://user.auth.xboxlive.com/user/authenticate"

	xboxAuthRequest := XboxLiveAuthRequest{
		RelyingParty: "http://auth.xboxlive.com",
		TokenType:    "JWT",
	}
	xboxAuthRequest.Properties.AuthMethod = "RPS"
	xboxAuthRequest.Properties.SiteName = "user.auth.xboxlive.com"
	xboxAuthRequest.Properties.RpsTicket = "d=" + accessToken

	reqBody, err := json.Marshal(xboxAuthRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal xbox auth request: %v", err)
	}

	resp, err := http.Post(xboxAuthURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send xbox auth request: %v", err)
	}
	defer resp.Body.Close()

	var xboxAuthResponse XboxLiveAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&xboxAuthResponse); err != nil {
		return nil, fmt.Errorf("failed to decode xbox auth response: %v", err)
	}

	return &xboxAuthResponse, nil
}

func getXSTSToken(xblToken string) (*XSTSAuthResponse, error) {
	xstsAuthURL := "https://xsts.auth.xboxlive.com/xsts/authorize"

	xstsAuthRequest := XSTSAuthRequest{
		RelyingParty: "rp://api.minecraftservices.com/",
		TokenType:    "JWT",
	}
	xstsAuthRequest.Properties.SandboxId = "RETAIL"
	xstsAuthRequest.Properties.UserTokens = []string{xblToken}

	reqBody, err := json.Marshal(xstsAuthRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal xsts auth request: %v", err)
	}

	resp, err := http.Post(xstsAuthURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send xsts auth request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xsts auth request failed with status code: %d", resp.StatusCode)
	}

	var xstsAuthResponse XSTSAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&xstsAuthResponse); err != nil {
		return nil, fmt.Errorf("failed to decode xsts auth response: %v", err)
	}

	return &xstsAuthResponse, nil
}

func authenticateWithMinecraft(userHash, xstsToken string) (*MinecraftAuthResponse, error) {
	minecraftPayload := map[string]interface{}{
		"identityToken": fmt.Sprintf("XBL3.0 x=%s;%s", userHash, xstsToken),
	}

	jsonData, err := json.Marshal(minecraftPayload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://api.minecraftservices.com/authentication/login_with_xbox", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to authenticate with Minecraft: %s", resp.Status)
	}

	var response MinecraftAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

func checkGameOwnership(accessToken string) (*GameOwnershipResponse, error) {
	url := "https://api.minecraftservices.com/entitlements/mcstore"

	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set the Authorization header
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to check game ownership: %s", resp.Status)
	}

	// Decode the response
	var ownershipResponse GameOwnershipResponse
	if err := json.NewDecoder(resp.Body).Decode(&ownershipResponse); err != nil {
		return nil, err
	}

	return &ownershipResponse, nil
}

func pollHandler(deviceCode *DeviceCodeResponse, usr string, proofStr *int64) (string, RegistrationResponse, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if deviceCode == nil {
		return "", RegistrationResponse{}, fmt.Errorf("Device code not found. Please start the login process again.")
	}

	// Get the access token using the device code
	tokenResponse, err := getAuthToken(deviceCode)
	if err != nil {
		log.Printf("Failed to get auth token: %v", err)
		return "", RegistrationResponse{}, fmt.Errorf("Failed to get auth token.")
	}

	// Authenticate with Xbox Live using the access token
	xboxLiveResponse, err := authenticateWithXboxLive(tokenResponse.AccessToken)
	if err != nil {
		log.Printf("Failed to authenticate with Xbox Live: %v", err)
		return "", RegistrationResponse{}, fmt.Errorf("Failed to authenticate with Xbox Live.")
	}

	// Obtain XSTS token using the Xbox Live token
	xstsResponse, err := getXSTSToken(xboxLiveResponse.Token)
	if err != nil {
		log.Printf("Failed to obtain XSTS token: %v", err)
		return "", RegistrationResponse{}, fmt.Errorf("Failed to obtain XSTS token.")
	}

	// Authenticate with Minecraft using the XSTS token and Xbox user hash
	minecraftAuthResponse, err := authenticateWithMinecraft(xstsResponse.DisplayClaims.Xui[0].Uhs, xstsResponse.Token)
	if err != nil {
		log.Printf("Failed to authenticate with Minecraft: %v", err)
		return "", RegistrationResponse{}, fmt.Errorf("Failed to authenticate with Minecraft.")
	}
	minecraftAccessToken := minecraftAuthResponse.AccessToken

	// Check game ownership
	ownershipResponse, err := checkGameOwnership(minecraftAccessToken)
	if err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to check game ownership: %v", err)
	}

	// Convert the minecraftAccessToken to a string (if it's not already a string)
	stringcraft := fmt.Sprintf("%s", minecraftAccessToken)

	// Split the JWT token into its parts
	jwtParts := strings.Split(stringcraft, ".")
	if len(jwtParts) < 2 {
		return "", RegistrationResponse{}, fmt.Errorf("Invalid JWT token format")
	}

	payload := jwtParts[1]
	decoded, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to decode JWT token: %v", err)
	}

	// JSON unmarshal the decoded JWT token into a map
	var decodedToken map[string]interface{}
	err = json.Unmarshal(decoded, &decodedToken)
	if err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to unmarshal decoded JWT token: %v", err)
	}

	// Attempt to retrieve the "profiles" key from the decoded token
	profiles, ok := decodedToken["profiles"]
	if !ok {
		return "", RegistrationResponse{}, fmt.Errorf("No profiles field found in JWT token")
	}

	// Handle different possible types for the "profiles" field
	var uuid string
	switch profiles := profiles.(type) {
	case map[string]interface{}:
		if mcProfile, ok := profiles["mc"].(string); ok {
			uuid = mcProfile
		} else {
			return "", RegistrationResponse{}, fmt.Errorf("mc profile not found or is not a string")
		}
	case string:
		uuid = profiles // if the profiles field is directly the UUID string
	default:
		return "", RegistrationResponse{}, fmt.Errorf("Unexpected type for profiles field")
	}

	// Remove the "-" from the UUID
	uuid = strings.ReplaceAll(uuid, "-", "")

	// Prepare the request to Mojang API
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.mojang.com/users/profiles/minecraft/%s", usr), nil)
	if err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to create request: %v", err)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", RegistrationResponse{}, fmt.Errorf("Request failed with status: %s", resp.Status)
	}

	// Decode the response
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", RegistrationResponse{}, fmt.Errorf("Failed to decode response: %v", err)
	}

	// Extract the UUID from the response
	userUUID, ok := user["id"].(string)
	if !ok {
		return "", RegistrationResponse{}, fmt.Errorf("UUID not found or is not a string")
	}

	// Compare the UUIDs
	if uuid != userUUID {
		return "", RegistrationResponse{}, fmt.Errorf("UUIDs do not match, impersonating someone is not nice!")
	}

	// Determine if the game is owned
	ownsGame := false
	for _, item := range ownershipResponse.Items {
		if item.Name == "game_minecraft" {
			ownsGame = true
			break
		}
	}

	// Render the result
	if ownsGame {
		// Generate a single-use token for the registration.
		atomic.StoreInt64(proofStr, time.Now().UnixNano())

		proof := atomic.LoadInt64(proofStr)

		// Build the RegistrationResponse struct
		registrationResponse := RegistrationResponse{
			Username: usr,
			Proof:    proof,
		}
		return "Account registered", registrationResponse, nil
	} else {
		return "Invalid ownership", RegistrationResponse{}, nil
	}
}
