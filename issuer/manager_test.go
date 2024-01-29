package issuer

import (
	"github.com/1f349/tulip/utils"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var testAddrUrl = func() utils.JsonUrl {
	a, err := url.Parse("https://example.com")
	if err != nil {
		panic(err)
	}
	return utils.JsonUrl{URL: a}
}()

func testBody() io.ReadCloser {
	return io.NopCloser(strings.NewReader("{}"))
}

func TestManager_CheckNamespace(t *testing.T) {
	httpGet = func(url string) (resp *http.Response, err error) {
		return &http.Response{StatusCode: http.StatusOK, Body: testBody()}, nil
	}
	manager, err := NewManager([]SsoConfig{
		{
			Addr:      testAddrUrl,
			Namespace: "example.com",
		},
	})
	assert.NoError(t, err)
	assert.True(t, manager.CheckNamespace("example.com"))
	assert.False(t, manager.CheckNamespace("missing.example.com"))
}

func TestManager_FindServiceFromLogin(t *testing.T) {
	httpGet = func(url string) (resp *http.Response, err error) {
		return &http.Response{StatusCode: http.StatusOK, Body: testBody()}, nil
	}
	manager, err := NewManager([]SsoConfig{
		{
			Addr:      testAddrUrl,
			Namespace: "example.com",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, manager.FindServiceFromLogin("jane@example.com"), manager.m["example.com"])
	assert.Nil(t, manager.FindServiceFromLogin("jane@missing.example.com"))
}
