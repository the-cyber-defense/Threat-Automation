package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- Configuration ---
var (
	tenantID        = os.Getenv("AZURE_TENANT_ID")
	clientID        = os.Getenv("AZURE_CLIENT_ID")
	clientSecret    = os.Getenv("AZURE_CLIENT_SECRET")
	graphAPIEndpoint = "https://graph.microsoft.com/v1.0"
	// For PIM eligibility automation
	// You can get Role Definition IDs from Azure Portal or via Graph API:
	// GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=displayName eq 'User Administrator'
	userAdminRoleDefID      = "fe930be7-5e62-47db-91af-98c3a49a38b1" // Example: User Administrator
	mockLegacyAPIEndpoint = os.Getenv("MOCK_LEGACY_API_ENDPOINT") // e.g., "https://your-mock-api.free.beeceptor.com/users"
)

// --- Structs ---
type UserDetails struct {
	DisplayName      string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	MailNickname     string `json:"mailNickname"`
	Password         string `json:"password"` // For demo; production should use secure generation/temp passwords
	AccountEnabled   bool   `json:"accountEnabled"`
}

// AzureADUser represents the structure for creating a user in AAD
type AzureADUser struct {
	AccountEnabled    bool          `json:"accountEnabled"`
	DisplayName       string        `json:"displayName"`
	MailNickname      string        `json:"mailNickname"`
	UserPrincipalName string        `json:"userPrincipalName"`
	PasswordProfile   PasswordProfile `json:"passwordProfile"`
}

type PasswordProfile struct {
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
	Password                      string `json:"password"`
}

// GraphErrorResponse for better error handling
type GraphErrorResponse struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		InnerError struct {
			Date            string `json:"date"`
			RequestID       string `json:"request-id"`
			ClientRequestID string `json:"client-request-id"`
		} `json:"innerError"`
	} `json:"error"`
}

// PIMEligibilityRequest structure for MS Graph PIM
type PIMEligibilityRequest struct {
	Action           string `json:"action"`
	Justification    string `json:"justification,omitempty"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	DirectoryScopeID string `json:"directoryScopeId"`
	ScheduleInfo     struct {
		StartDateTime string `json:"startDateTime,omitempty"`
		Expiration    struct {
			Type     string `json:"type"`
			Duration string `json:"duration,omitempty"` // e.g., "PT2H"
			// EndDateTime string `json:"endDateTime,omitempty"`
		} `json:"expiration"`
	} `json:"scheduleInfo,omitempty"`
}

// Function to get an OAuth2 token for MS Graph API
func getGraphToken(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	data := fmt.Sprintf("client_id=%s&scope=https://graph.microsoft.com/.default&client_secret=%s&grant_type=client_credentials",
		clientID, clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get token, status: %s, body: %s", resp.Status, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal token response: %w", err)
	}
	return tokenResponse.AccessToken, nil
}

// Generic function to make a Graph API request
func makeGraphAPIRequest(ctx context.Context, method, url, token string, payload interface{}) ([]byte, int, error) {
	var reqBody []byte
	var err error

	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal payload: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create graph request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute graph request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read graph response body: %w", err)
	}

	if resp.StatusCode >= 300 { // Check for non-2xx status codes
		var graphErr GraphErrorResponse
		if json.Unmarshal(respBody, &graphErr) == nil && graphErr.Error.Message != "" {
			return respBody, resp.StatusCode, fmt.Errorf("graph API error [%s]: %s (Code: %s)", resp.Status, graphErr.Error.Message, graphErr.Error.Code)
		}
		return respBody, resp.StatusCode, fmt.Errorf("graph API error: status %s, body: %s", resp.Status, string(respBody))
	}

	return respBody, resp.StatusCode, nil
}

// Function to create a user in Azure AD
func createAzureADUser(ctx context.Context, token string, user UserDetails) (string, error) {
	log.Printf("Attempting to create user: %s", user.UserPrincipalName)

	aadUser := AzureADUser{
		AccountEnabled:    user.AccountEnabled,
		DisplayName:       user.DisplayName,
		MailNickname:      user.MailNickname,
		UserPrincipalName: user.UserPrincipalName,
		PasswordProfile: PasswordProfile{
			ForceChangePasswordNextSignIn: true,
			Password:                      user.Password,
		},
	}

	respBody, statusCode, err := makeGraphAPIRequest(ctx, "POST", graphAPIEndpoint+"/users", token, aadUser)
	if err != nil {
		return "", fmt.Errorf("failed to create AAD user: %w (Status: %d)", err, statusCode)
	}

	var createdUser struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &createdUser); err != nil {
		return "", fmt.Errorf("failed to unmarshal created user response: %w. Body: %s", err, string(respBody))
	}

	log.Printf("Successfully created Azure AD User: %s (ID: %s)", user.UserPrincipalName, createdUser.ID)
	return createdUser.ID, nil
}

// Function to assign PIM eligibility
func assignPIMEligibility(ctx context.Context, token, userID, roleDefID, justification string) error {
	log.Printf("Assigning PIM eligibility for role %s to user %s", roleDefID, userID)

	pimRequest := PIMEligibilityRequest{
		Action:           "adminAssign", // Use "adminAssign" to make a user eligible
		Justification:    justification,
		RoleDefinitionID: fmt.Sprintf("/roleManagement/directory/roleDefinitions/%s", roleDefID),
		PrincipalID:      userID,
		DirectoryScopeID: "/", //  Directory-wide scope (tenant)
		ScheduleInfo: struct {
			StartDateTime string `json:"startDateTime,omitempty"`
			Expiration    struct {
				Type     string `json:"type"`
				Duration string `json:"duration,omitempty"`
			} `json:"expiration"`
		}{
            // StartDateTime: time.Now().UTC().Format(time.RFC3339), // Eligibility starts now
			Expiration: struct {
				Type     string `json:"type"`
				Duration string `json:"duration,omitempty"`
			}{
				Type:     "permanent", // Or "afterDuration" with Duration: "P365D" for 1 year
				// Duration: "P365D",
			},
		},
	}
    
	// Note: The PIM API structure changed. For ELIGIBILITY it's roleEligibilityScheduleRequests
	// For ACTIVE assignment it's roleAssignmentScheduleRequests
	pimEndpoint := fmt.Sprintf("%s/roleManagement/directory/roleEligibilityScheduleRequests", graphAPIEndpoint)

	_, statusCode, err := makeGraphAPIRequest(ctx, "POST", pimEndpoint, token, pimRequest)
	if err != nil {
		return fmt.Errorf("failed to assign PIM eligibility: %w (Status: %d)", err, statusCode)
	}

	log.Printf("Successfully submitted PIM eligibility request for user %s, role %s. Status Code: %d", userID, roleDefID, statusCode)
	return nil
}


// Function to send user data to a mock legacy system
func createUserInLegacySystem(ctx context.Context, user UserDetails) error {
	if mockLegacyAPIEndpoint == "" {
		log.Println("MOCK_LEGACY_API_ENDPOINT not set. Skipping legacy system integration.")
		return nil
	}

	log.Printf("Attempting to create user in legacy system: %s", user.UserPrincipalName)

	// Prepare payload for the legacy system (can be different from AAD)
	legacyPayload := map[string]string{
		"username":   user.UserPrincipalName,
		"fullName":   user.DisplayName,
		"department": "New Hires", // Example field
	}

	jsonData, err := json.Marshal(legacyPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal legacy payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", mockLegacyAPIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create legacy system request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// req.Header.Set("X-API-Key", "LEGACY_SYSTEM_API_KEY") // If legacy system needs an API key

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send data to legacy system: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("legacy system API error: status %s, body: %s", resp.Status, string(respBody))
	}

	log.Printf("Successfully sent user data to legacy system for: %s. Status: %s", user.UserPrincipalName, resp.Status)
	return nil
}

func main() {
	ctx := context.Background()

	// --- Check for required environment variables ---
	if tenantID == "" || clientID == "" || clientSecret == "" {
		log.Fatal("Error: AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables must be set.")
	}

	// --- 1. Get MS Graph API Token ---
	token, err := getGraphToken(ctx)
	if err != nil {
		log.Fatalf("Error getting Graph API token: %v", err)
	}
	log.Println("Successfully obtained MS Graph API token.")

	// --- 2. Define New User Details ---
	// Ensure domain is valid for your tenant
	domain := strings.Split(os.Getenv("USERDOMAIN"), `\`)[1] // Or hardcode your tenant's domain
	if domain == "" {
		log.Fatal("Could not determine domain. Set USERDOMAIN or hardcode.")
	}


	newUser := UserDetails{
		DisplayName:      "GoLang Automated User",
		UserPrincipalName: fmt.Sprintf("golang.testuser%d@%s", time.Now().UnixNano()%10000, domain), // Ensure unique UPN
		MailNickname:     fmt.Sprintf("golang.testuser%d", time.Now().UnixNano()%10000),
		Password:         "P@$$wOrd12345!!", // Use a strong, secure password or generation mechanism
		AccountEnabled:   true,
	}
	log.Printf("New user UPN: %s", newUser.UserPrincipalName)


	// --- 3. Create User in Azure AD ---
	userID, err := createAzureADUser(ctx, token, newUser)
	if err != nil {
		log.Fatalf("Error creating Azure AD user: %v", err)
	}

	// --- 4. Assign PIM Eligibility (Optional) ---
	// This makes the user eligible for the "User Administrator" role.
	// They would then need to activate it through PIM.
	pimJustification := "Automated assignment for new critical GoLang user"
	err = assignPIMEligibility(ctx, token, userID, userAdminRoleDefID, pimJustification)
	if err != nil {
		// Log as warning because user creation might be the primary goal
		log.Printf("Warning: Failed to assign PIM eligibility: %v", err)
	}

	// --- 5. Integrate with Legacy System ---
	err = createUserInLegacySystem(ctx, newUser)
	if err != nil {
		log.Printf("Warning: Failed to create user in legacy system: %v", err)
	}

	log.Println("--- Identity Onboarding Process Completed ---")
	log.Printf("Successfully processed user: %s (Azure AD ID: %s)", newUser.UserPrincipalName, userID)
}
