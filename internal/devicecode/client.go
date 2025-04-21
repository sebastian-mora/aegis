package devicecode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type DeviceCodeRequestResponse struct {
	DeviceCode       string `json:"device_code"`
	UserCode         string `json:"user_code"`
	VerfificationURI string `json:"verification_uri_complete"`
	Interval         int    `json:"interval"`
	ExpiresIn        int    `json:"expires_in"`
}

type DeviceCodeTokenResponse struct {
	AccessToken string `json:"access_token"`
	IdToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type DeviceCoder interface {
	RequestDeviceCode(ctx context.Context) (*DeviceCodeRequestResponse, error)
	PollDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeRequestResponse, error)
}

type DeviceCodeAuthentik struct {
	AuthDomain string
	ClientID   string
	Scope      string
}

func NewDeviceCodeAuthentik(authDomain, clientID, scope string) *DeviceCodeAuthentik {
	return &DeviceCodeAuthentik{
		AuthDomain: authDomain,
		ClientID:   clientID,
		Scope:      scope,
	}
}
func (d *DeviceCodeAuthentik) RequestDeviceCode() (*DeviceCodeRequestResponse, error) {
	resp, err := http.PostForm(d.AuthDomain+"/application/o/device/", url.Values{
		"client_id": {d.ClientID},
		"scope":     {d.Scope},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get device code: %s", string(body))
	}
	var oauthResp DeviceCodeRequestResponse
	err = json.Unmarshal(body, &oauthResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &oauthResp, nil
}

func (d *DeviceCodeAuthentik) PollDeviceCode(ctx context.Context, deviceCodeRequest DeviceCodeRequestResponse) (*DeviceCodeTokenResponse, error) {
	ticker := time.NewTicker(time.Duration(deviceCodeRequest.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-ticker.C:
			resp, err := d.checkDeviceCode(ctx, deviceCodeRequest.DeviceCode)

			if err != nil {
				return nil, fmt.Errorf("failed to poll device code: %w", err)
			}

			// if we reccived a token, return it
			if resp != nil && resp.AccessToken != "" {
				return resp, nil
			}

		}
	}
}

func (d *DeviceCodeAuthentik) checkDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeTokenResponse, error) {
	resp, err := http.PostForm(d.AuthDomain+"/application/o/token/", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {d.ClientID},
		"device_code": {deviceCode},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check device code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Parse error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %s", string(body))
		}

		switch errResp.Error {
		case "authorization_pending":
			return nil, nil // expected, continue polling
		default:
			return nil, fmt.Errorf("failed to poll check code: %s", errResp.ErrorDescription)
		}
	}

	var tokenResponse DeviceCodeTokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse check code response: %w", err)
	}

	return &tokenResponse, nil
}
