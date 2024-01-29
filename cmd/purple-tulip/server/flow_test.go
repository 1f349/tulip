package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/mjwt"
	"github.com/1f349/tulip/cmd/purple-tulip/pages"
	"github.com/1f349/tulip/issuer"
	"github.com/1f349/tulip/utils"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"
)

const lavenderDomain = "http://localhost:0"
const clientAppDomain = "http://localhost:1"
const loginDomain = "http://localhost:2"

var clientAppMeta AllowedClient

var testSigner mjwt.Signer

var testOidc = &issuer.WellKnownOIDC{
	Config: issuer.SsoConfig{
		Addr:      utils.JsonUrl{},
		Namespace: "example.com",
		Client: issuer.SsoConfigClient{
			ID:     "test-id",
			Secret: "test-secret",
			Scopes: []string{"openid"},
		},
	},
	Issuer:                 "https://example.com",
	AuthorizationEndpoint:  loginDomain + "/authorize",
	TokenEndpoint:          loginDomain + "/token",
	UserInfoEndpoint:       loginDomain + "/userinfo",
	ResponseTypesSupported: nil,
	ScopesSupported:        nil,
	ClaimsSupported:        nil,
	GrantTypesSupported:    nil,
	OAuth2Config: oauth2.Config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   loginDomain + "/authorize",
			TokenURL:  loginDomain + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: nil,
	},
}

var testManager = issuer.NewManagerForTests([]*issuer.WellKnownOIDC{testOidc})
var testHttpServer = HttpServer{
	r:         nil,
	flowState: cache.New[string, flowStateData](),
}

func init() {
	testHttpServer.conf.Store(&Conf{
		BaseUrl:     lavenderDomain,
		ServiceName: "Test Purple Tulip Service",
	})
	testHttpServer.manager.Store(testManager)
	testHttpServer.services.Store(&map[string]AllowedClient{
		clientAppDomain: {},
	})

	err := pages.LoadPages("")
	if err != nil {
		panic(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	testSigner = mjwt.NewMJwtSigner("https://example.com", key)
	testHttpServer.signer = testSigner

	parse, err := url.Parse(clientAppDomain)
	if err != nil {
		panic(err)
	}

	clientAppMeta = AllowedClient{
		Url:         utils.JsonUrl{URL: parse},
		Permissions: []string{"test-perm"},
	}
}

func TestFlowPopup(t *testing.T) {
	h := HttpServer{}
	h.conf.Store(&Conf{ServiceName: "Test Service Name"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/popup?"+url.Values{"origin": []string{clientAppDomain}}.Encode(), nil)
	h.flowPopup(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <title>Test Service Name</title>
    <link rel="stylesheet" href="/theme/style.css">
</head>
<body>
<header>
    <h1>Test Service Name</h1>
</header>
<main>
    <form method="POST" action="/popup">
        <input type="hidden" name="origin" value="%s"/>
        <div>
            <label for="field_loginname">Login Name:</label>
            <input type="text" name="loginname" id="field_loginname" required/>
        </div>
        <button type="submit">Continue</button>
    </form>
</main>
</body>
</html>
`, clientAppDomain), rec.Body.String())
}

func TestFlowPopupPost(t *testing.T) {
	// test no login service error
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@missing.example.com"},
		"origin":    []string{clientAppDomain},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "No login service defined for this username\n", rec.Body.String())

	// test invalid target origin error
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@example.com"},
		"origin":    []string{"http://localhost:1010"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Invalid target origin\n", rec.Body.String())

	// test successful request
	nextState := uuid.NewString()
	uuidNewStringState = func() string { return nextState }
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@example.com"},
		"origin":    []string{clientAppDomain},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "", rec.Body.String())
	assert.Equal(t, loginDomain+"/authorize?"+url.Values{
		"client_id":     []string{"test-id"},
		"login_name":    []string{"test"},
		"redirect_uri":  []string{lavenderDomain + "/callback"},
		"response_type": []string{"code"},
		"state":         []string{"example.com:" + nextState},
	}.Encode(), rec.Header().Get("Location"))
}

func TestFlowCallback(t *testing.T) {
	expiryTime := time.Now().Add(15 * time.Minute)
	nextState := uuid.NewString()
	testHttpServer.flowState.Set("example.com:"+nextState, flowStateData{
		sso:    testOidc,
		target: clientAppMeta,
	}, expiryTime)

	testOa2Exchange = func(oa2conf oauth2.Config, ctx context.Context, code string) (*oauth2.Token, error) {
		return nil, errors.New("no exchange should be made")
	}
	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		return nil, errors.New("no userinfo should be fetched")
	}

	// test parse form error
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?%+"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Error parsing form\n", rec.Body.String())

	// test invalid namespace
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"missing.example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Invalid state namespace\n", rec.Body.String())

	// test invalid state
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:invalid"},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Invalid state\n", rec.Body.String())

	// test failed exchange
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Failed to exchange code\n", rec.Body.String())

	testOa2Exchange = func(oa2conf oauth2.Config, ctx context.Context, code string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "abcd1234",
			TokenType:    "",
			RefreshToken: "efgh5678",
			Expiry:       expiryTime,
		}, nil
	}

	// test failed userinfo
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Failed to get userinfo\n", rec.Body.String())

	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusInternalServerError)
		return rec.Result(), nil
	}

	// test failed userinfo status code
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Failed to get userinfo: unexpected status code\n", rec.Body.String())

	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Body.WriteString("{")
		return rec.Result(), nil
	}

	// test failed userinfo decode
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Failed to decode userinfo\n", rec.Body.String())

	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Body.WriteString("{\"sub\":1}")
		return rec.Result(), nil
	}

	// test invalid subject in userinfo
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Invalid subject in userinfo\n", rec.Body.String())

	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Body.WriteString("{\"sub\":\"1\",\"aud\":1}")
		return rec.Result(), nil
	}

	// test invalid audience in userinfo
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "Invalid audience in userinfo\n", rec.Body.String())

	testOa2UserInfo = func(oidc *issuer.WellKnownOIDC, ctx context.Context, exchange *oauth2.Token) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Body.WriteString(fmt.Sprintf(`{
  "sub": "test-user",
  "aud": "%s",
  "test-field": "ok"
}
`, clientAppDomain))
		return rec.Result(), nil
	}

	// test successful request
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"state":  []string{"example.com:" + nextState},
		"origin": []string{clientAppDomain},
	}.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testHttpServer.flowCallback(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusOK, rec.Code)
	const p1 = `<!DOCTYPE html>
<html lang="en">
<head>
    <title>Test Purple Tulip Service</title>
    <link rel="stylesheet" href="/theme/style.css">
    <script>
        let loginData = {
            target:"%s",
            tokens: `
	const p2 = `,
            userinfo:{"aud":"%s","sub":"test-user","test-field":"ok"},
        };
        window.addEventListener("load", function () {
            window.opener.postMessage(loginData, loginData.target);
            setTimeout(function () {
                window.close();
            }, 500);
        });
    </script>
</head>
<body>
<header>
    <h1>Test Purple Tulip Service</h1>
</header>
<main id="mainBody">Loading...</main>
</body>
</html>
`
	var p1v = fmt.Sprintf(p1, clientAppDomain)
	var p2v = fmt.Sprintf(p2, clientAppDomain)

	a := make([]byte, len(p1v))
	n, err := rec.Body.Read(a)
	assert.NoError(t, err)
	assert.Equal(t, len(p1v), n)
	assert.Equal(t, p1v, string(a))

	var accessToken, refreshToken string
	findByte(rec.Body, '{')
	findString(rec.Body, "access:")
	readQuotedString(rec.Body, &accessToken)
	findByte(rec.Body, ',')
	findString(rec.Body, "refresh:")
	readQuotedString(rec.Body, &refreshToken)
	findByte(rec.Body, ',')
	findByte(rec.Body, '}')

	assert.Equal(t, p2v, rec.Body.String())
}

func findByte(buf *bytes.Buffer, v byte) {
	for {
		readByte, err := buf.ReadByte()
		if err != nil {
			panic(err)
		}
		if readByte == v {
			break
		}
		if !unicode.IsSpace(rune(readByte)) {
			panic(fmt.Sprint("Found non space rune: ", readByte))
		}
	}
}

func findString(buf *bytes.Buffer, v string) {
	if len(v) == 0 {
		panic("Cannot find empty string")
	}
	findByte(buf, v[0])
	if len(v) > 1 {
		a2 := make([]byte, len(v)-1)
		n, err := buf.Read(a2)
		if err != nil {
			panic(err)
		}
		if n != len(a2) {
			panic("Probably found end of buffer")
		}
		if bytes.Compare([]byte(v[1:]), a2) != 0 {
			panic("Failed to find string in buffer")
		}
	}
}

func readQuotedString(buf *bytes.Buffer, p *string) {
	findByte(buf, '"')
	b, err := buf.ReadBytes('"')
	if err != nil {
		panic(err)
	}
	*p = string(b)
}
