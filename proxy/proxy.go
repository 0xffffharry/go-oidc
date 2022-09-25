package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oidc/cachemap"
	clog "oidc/log"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SessionDefaultExpiredTime      = 600 * time.Second
	SessionLoginDefaultExpiredTime = 3600 * time.Second
)

type ProxyConfig struct {
	Tag            string   `json:"tag"`
	Listen         string   `json:"listen"`
	DiscoveryUri   string   `json:"discovery_uri"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	RedirectPath   string   `json:"redirect_path"`
	LogoutPath     string   `json:"logout_path"`
	AfterLogoutUri string   `json:"after_logout_uri"`
	Scope          []string `json:"scope"`
	Upstream       string   `json:"upstream"`
	HTTPLog        bool     `json:"http_log"`
}

type Global struct {
	ProxyConfig []ProxyConfig
	Ctx         context.Context
	Logger      *clog.Logger
}

type global struct {
	Ctx    context.Context
	Logger *clog.Logger
}

type proxy struct {
	Global     *global
	Config     ProxyConfig
	HTTPClient *http.Client
	//
	OpenidConfig openIDConfig
	//
	SessionCache      *cachemap.CacheMap
	SessionLoginCache *cachemap.CacheMap
	//
	ReverseProxyLogger *log.Logger
}

type openIDConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type responseTokenStruct struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type tokenStruct struct {
	AccessToken  string
	RefreshToken string
	ExpiredTime  time.Time
}

func (g *Global) Run() {
	global := &global{
		Ctx:    g.Ctx,
		Logger: g.Logger,
	}
	gin.SetMode(gin.ReleaseMode)
	wg := sync.WaitGroup{}
	for _, config := range g.ProxyConfig {
		p := &proxy{
			Global: global,
			Config: config,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Global.Logger.Println(clog.Info, fmt.Sprintf("proxy %s start", p.Config.Tag))
			p.newProxy()
		}()
	}
	wg.Wait()
}

func (p *proxy) newProxy() {
	if p.HTTPClient == nil {
		client := &http.Client{Transport: http.DefaultTransport}
		p.HTTPClient = client
	}
	var discoveryResponse *http.Response
	for {
		discoveryRequest, err := http.NewRequestWithContext(p.Global.Ctx, http.MethodGet, p.Config.DiscoveryUri, nil)
		if err != nil {
			p.Global.Logger.Println(clog.Error, err, "Retry in 3 seconds...")
			time.Sleep(3 * time.Second)
			continue
		}
		discoveryResponse, err = p.HTTPClient.Do(discoveryRequest)
		if err != nil {
			p.Global.Logger.Println(clog.Error, err, "Retry in 3 seconds...")
			time.Sleep(3 * time.Second)
			continue
		}
		if discoveryResponse.StatusCode != http.StatusOK {
			p.Global.Logger.Fatalln(clog.Fatal, "Discovery request failed with status code:", discoveryResponse.StatusCode)
			return
		}
		break
	}
	var openidConfiguration openIDConfig
	err := json.NewDecoder(discoveryResponse.Body).Decode(&openidConfiguration)
	if err != nil {
		p.Global.Logger.Fatalln(clog.Fatal, "Discovery request json parse fail: ", err)
		return
	}
	_ = discoveryResponse.Body.Close()
	p.OpenidConfig = openidConfiguration
	p.SessionCache = cachemap.New(p.Global.Ctx, 1*time.Second)
	p.SessionLoginCache = cachemap.New(p.Global.Ctx, 1*time.Second)
	router := gin.New()
	ginLoggerConfig := gin.LoggerConfig{}
	if p.Config.HTTPLog {
		ginLoggerConfig.Output = p.Global.Logger.SetReceiverToWriter(clog.CustomLevel("Gin Server - "+p.Config.Tag), func(level string, str string) string {
			return fmt.Sprintf("[%s] [%s] %s", time.Now().Format("2006-01-02 15:04:05 UTC-07"), level, str)
		})
		ginLoggerConfig.Formatter = func(params gin.LogFormatterParams) string {
			return fmt.Sprintf("%s %s %s %s %s\n", strconv.Itoa(params.StatusCode), params.ClientIP, params.Method, params.Path, params.ErrorMessage)
		}
	} else {
		ginLoggerConfig.Output = io.Discard
		ginLoggerConfig.Formatter = func(params gin.LogFormatterParams) string {
			return ""
		}
	}
	router.Use(gin.LoggerWithConfig(ginLoggerConfig))
	router.GET(p.Config.RedirectPath, func(c *gin.Context) {
		p.redirectHandler(c)
	})
	router.GET(p.Config.LogoutPath, func(c *gin.Context) {
		p.logoutHandler(c)
	})
	router.NoRoute(func(c *gin.Context) {
		p.defaultHandler(c)
	})
	p.ReverseProxyLogger = p.Global.Logger.SetReceiverToLogger(clog.CustomLevel("ReverseProxy - "+p.Config.Tag), func(level string, str string) string {
		return fmt.Sprintf("[%s] [%s] %s", time.Now().Format("2006-01-02 15:04:05 UTC-07"), level, str)
	})
	serverLogger := p.Global.Logger.SetReceiverToLogger(clog.CustomLevel("HTTP Server"), nil)
	server := http.Server{}
	server.Handler = router
	server.Addr = p.Config.Listen
	server.ErrorLog = serverLogger
	go func() {
		<-p.Global.Ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	p.Global.Logger.Println(clog.Info, "Gin Server - "+p.Config.Tag+" start at ", p.Config.Listen)
	err = server.ListenAndServe()
	if err != nil {
		if err == http.ErrServerClosed {
			p.Global.Logger.Println(clog.Warning, fmt.Sprintf("[Gin Server - %s]: server closed", p.Config.Tag))
			return
		}
		p.Global.Logger.Fatalln(clog.Warning, fmt.Sprintf("[Gin Server - %s]: %s", p.Config.Tag, err))
	}
}

func (p *proxy) tokenManager(authID string, token tokenStruct, username string) {
	tokenCache := token
	tokenCacheLock := sync.RWMutex{}
	logoutChan := make(chan struct{}, 1)
	defer close(logoutChan)
	go func() {
		for {
			select {
			case <-p.Global.Ctx.Done():
				return
			case <-time.After(2 * time.Second):
				tokenCacheLock.RLock()
				AccessTokenRead := tokenCache.AccessToken
				tokenCacheLock.RUnlock()
				if AccessTokenRead == "" {
					return
				}
				valid, _ := p.authTokenValid(AccessTokenRead)
				if !valid {
					logoutChan <- struct{}{}
					return
				}
			}
		}
	}()
	for {
		select {
		case <-p.Global.Ctx.Done():
			return
		case <-logoutChan:
			_ = p.SessionLoginCache.Delete(authID)
			p.Global.Logger.Println(clog.Info, "Logout success, username: ", username)
			return
		case <-time.After(2 * time.Second):
			if p.SessionLoginCache.Exist(authID) {
				tokenCacheLock.RLock()
				if time.Now().Add(-60 * time.Second).After(tokenCache.ExpiredTime) {
					refreshQuery := url.Values{}
					refreshQuery.Set("grant_type", "refresh_token")
					refreshQuery.Set("refresh_token", tokenCache.RefreshToken)
					tokenCacheLock.RUnlock()
					refreshQuery.Set("client_id", p.Config.ClientID)
					refreshQuery.Set("client_secret", p.Config.ClientSecret)
					var refreshResponse *http.Response
					retry := 3
					for {
						refreshRequest, err := http.NewRequestWithContext(p.Global.Ctx, http.MethodPost, p.OpenidConfig.TokenEndpoint, strings.NewReader(refreshQuery.Encode()))
						if err != nil {
							p.Global.Logger.Println(clog.Error, fmt.Sprintf("Refresh Token request failed: %s", err))
							if retry > 0 {
								retry--
								continue
							} else {
								_ = p.SessionLoginCache.Delete(authID)
								return
							}
						}
						refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						refreshResponse, err = p.HTTPClient.Do(refreshRequest)
						if err != nil {
							p.Global.Logger.Println(clog.Error, fmt.Sprintf("Refresh Token request failed: %s", err))
							if retry > 0 {
								retry--
								continue
							} else {
								_ = p.SessionLoginCache.Delete(authID)
								return
							}
						}
						break
					}
					if refreshResponse.StatusCode != http.StatusOK {
						p.Global.Logger.Println(clog.Error, fmt.Sprintf("Refresh Token request failed: %d", refreshResponse.StatusCode))
						_ = p.SessionLoginCache.Delete(authID)
						return
					}
					rawDataBuf := bytes.NewBuffer(nil)
					_, err := io.Copy(rawDataBuf, refreshResponse.Body)
					if err != nil {
						p.Global.Logger.Println(clog.Error, fmt.Sprintf("Refresh Token request read failed: %s", err))
						_ = p.SessionLoginCache.Delete(authID)
						return
					}
					var newToken responseTokenStruct
					err = json.Unmarshal(rawDataBuf.Bytes(), &newToken)
					if err != nil {
						p.Global.Logger.Println(clog.Error, fmt.Sprintf("Refresh Token request json parse failed: %s", err))
						_ = p.SessionLoginCache.Delete(authID)
						return
					}
					_ = refreshResponse.Body.Close()
					tokenCacheLock.Lock()
					tokenCache.AccessToken = newToken.AccessToken
					tokenCache.RefreshToken = newToken.RefreshToken
					tokenCache.ExpiredTime = time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
					tokenCacheLock.Unlock()
					p.Global.Logger.Println(clog.Info, "Refresh Token success")
				} else {
					tokenCacheLock.RUnlock()
					continue
				}
			} else {
				logoutQuery := url.Values{}
				tokenCacheLock.RLock()
				logoutQuery.Set("refresh_token", tokenCache.RefreshToken)
				tokenCacheLock.RUnlock()
				logoutQuery.Set("client_id", p.Config.ClientID)
				logoutQuery.Set("client_secret", p.Config.ClientSecret)
				var logoutResponse *http.Response
				retry := 3
				for {
					logoutRequest, err := http.NewRequestWithContext(p.Global.Ctx, http.MethodGet, p.OpenidConfig.EndSessionEndpoint, strings.NewReader(logoutQuery.Encode()))
					if err != nil {
						p.Global.Logger.Println(clog.Error, fmt.Sprintf("Logout request failed: %s", err))
						if retry > 0 {
							retry--
							continue
						} else {
							_ = p.SessionLoginCache.Delete(authID)
							return
						}
					}
					logoutRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					logoutResponse, err = p.HTTPClient.Do(logoutRequest)
					if err != nil {
						p.Global.Logger.Println(clog.Error, fmt.Sprintf("Logout request failed: %s", err))
						if retry > 0 {
							retry--
							continue
						} else {
							_ = p.SessionLoginCache.Delete(authID)
							return
						}
					}
					break
				}
				if logoutResponse.StatusCode != http.StatusOK && logoutResponse.StatusCode != http.StatusNoContent {
					p.Global.Logger.Println(clog.Error, fmt.Sprintf("Logout request failed with status code: %d", logoutResponse.StatusCode))
					_ = p.SessionLoginCache.Delete(authID)
					return
				}
				p.Global.Logger.Println(clog.Info, "Logout success, username: ", username)
				_ = p.SessionLoginCache.Delete(authID)
				return
			}
		}
	}
}

func (p *proxy) getReal(c *gin.Context) (map[string]string, error) {
	m := make(map[string]string)
	XForwardedFor := c.GetHeader("X-Forwarded-For")
	XForwardedProto := c.GetHeader("X-Forwarded-Proto")
	XForwardedHost := c.GetHeader("X-Forwarded-Host")
	XForwardedPort := c.GetHeader("X-Forwarded-Port")
	XReal := c.GetHeader("X-Real")
	//
	if XForwardedProto == "" {
		return nil, errors.New("X-Forwarded-Proto is empty")
	} else {
		m["Proto"] = XForwardedProto
	}
	if XForwardedHost == "" {
		return nil, errors.New("X-Forwarded-Host is empty")
	} else {
		m["Host"] = XForwardedHost
	}
	if XForwardedPort == "" {
		return nil, errors.New("X-Forwarded-Port is empty")
	} else {
		m["Port"] = XForwardedPort
	}
	if XReal == "" && XForwardedFor == "" {
		return nil, errors.New("X-Real and X-Forwarded-For is empty")
	} else {
		if XReal != "" {
			m["RealIP"] = XReal
		} else {
			m["RealIP"] = strings.Split(XForwardedFor, ", ")[0]
		}
	}
	//
	switch XForwardedProto {
	case "http":
		if XForwardedPort == "80" {
			a := strings.Split(net.JoinHostPort(XForwardedHost, ""), ":")
			m["HostWithPort"] = strings.Join(a[:len(a)-1], ":")
		} else {
			m["HostWithPort"] = net.JoinHostPort(XForwardedHost, XForwardedPort)
		}
	case "https":
		if XForwardedPort == "443" {
			a := strings.Split(net.JoinHostPort(XForwardedHost, ""), ":")
			m["HostWithPort"] = strings.Join(a[:len(a)-1], ":")
		} else {
			m["HostWithPort"] = net.JoinHostPort(XForwardedHost, XForwardedPort)
		}
	default:
		return nil, errors.New("X-Forwarded-Proto is not http or https")
	}
	return m, nil
}

func random(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func (p *proxy) authTokenValid(accessToken string) (bool, string) {
	q := url.Values{}
	q.Add("token", accessToken)
	q.Add("client_id", p.Config.ClientID)
	q.Add("client_secret", p.Config.ClientSecret)
	retry := 3
	for {
		req, err := http.NewRequestWithContext(p.Global.Ctx, http.MethodPost, p.OpenidConfig.IntrospectionEndpoint, strings.NewReader(q.Encode()))
		if err != nil {
			p.Global.Logger.Println(clog.Error, fmt.Sprintf("token auth valid fail: request fail: %s", err))
			if retry > 0 {
				retry--
				continue
			} else {
				return false, ""
			}
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := p.HTTPClient.Do(req)
		if err != nil {
			p.Global.Logger.Println(clog.Error, fmt.Sprintf("token auth valid fail: request fail: %s", err))
			if retry > 0 {
				retry--
				continue
			} else {
				return false, ""
			}
		}
		rawDataBuf := bytes.NewBuffer(nil)
		_, err = io.Copy(rawDataBuf, resp.Body)
		if err != nil {
			p.Global.Logger.Println(clog.Error, fmt.Sprintf("token auth valid fail: read fail: %s", err))
			return false, ""
		}
		type ResponseStruct struct {
			Active   bool   `json:"active"`
			Username string `json:"name"`
		}
		var r ResponseStruct
		err = json.Unmarshal(rawDataBuf.Bytes(), &r)
		if err != nil {
			p.Global.Logger.Println(clog.Error, fmt.Sprintf("token auth valid fail: json parse fail: %s", err))
			return false, ""
		}
		return r.Active, r.Username
	}
}

func (p *proxy) redirectHandler(c *gin.Context) {
	ConnectionID := random(8)
	realMap, err := p.getReal(c)
	if err != nil {
		p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] %s", ConnectionID, err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "400 Bad Request",
		})
		return
	}
	QueryCode := c.Query("code")
	QueryState := c.Query("state")
	if QueryCode == "" || QueryState == "" {
		authCookie, err := c.Cookie("auth")
		if err == nil {
			if p.SessionLoginCache.Exist(authCookie) {
				_ = p.SessionLoginCache.SetTTL(authCookie, SessionLoginDefaultExpiredTime)
				c.Redirect(http.StatusFound, "/")
				return
			}
		}
		p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] %s", ConnectionID, "code or state is empty"))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "400 Bad Request",
		})
		return
	}
	if !p.SessionCache.Exist(QueryState) {
		p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] state invalid", ConnectionID))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "400 Bad Request",
		})
		return
	} else {
		_ = p.SessionCache.Delete(QueryState)
	}
	redirectUri := url.URL{}
	redirectUri.Scheme = realMap["Proto"]
	redirectUri.Host = realMap["HostWithPort"]
	redirectUri.Path = p.Config.RedirectPath
	requestTokenQuery := url.Values{}
	requestTokenQuery.Add("grant_type", "authorization_code")
	requestTokenQuery.Add("code", QueryCode)
	requestTokenQuery.Add("client_id", p.Config.ClientID)
	requestTokenQuery.Add("client_secret", p.Config.ClientSecret)
	requestTokenQuery.Add("redirect_uri", redirectUri.String())
	//
	requestTokenQueryEncode := requestTokenQuery.Encode()
	requestToken, err := http.NewRequestWithContext(p.Global.Ctx, http.MethodPost, p.OpenidConfig.TokenEndpoint, strings.NewReader(requestTokenQueryEncode))
	if err != nil {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] %s", ConnectionID, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	requestToken.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//
	responseToken, err := p.HTTPClient.Do(requestToken)
	if err != nil {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] request token fail: %s", ConnectionID, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	if responseToken.StatusCode != http.StatusOK {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] get token invalid status: %s", ConnectionID, responseToken.Status))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	rawDataBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(rawDataBuf, responseToken.Body)
	_ = requestToken.Body.Close()
	if err != nil {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] token read fail: %s", ConnectionID, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	var token responseTokenStruct
	err = json.Unmarshal(rawDataBuf.Bytes(), &token)
	if err != nil {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] token json parse fail: %s", ConnectionID, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	vaild, username := p.authTokenValid(token.AccessToken)
	if !vaild {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] token invalid", ConnectionID))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	err = p.SessionLoginCache.Set(cachemap.Config{
		Key:   QueryState,
		Value: nil,
		TTL:   SessionLoginDefaultExpiredTime,
	})
	if err != nil {
		p.Global.Logger.Println(clog.Error, fmt.Sprintf("[%s] session login cache add fail: %s", ConnectionID, err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "500 Internal Server Error",
		})
		return
	}
	go p.tokenManager(QueryState, tokenStruct{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiredTime:  time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
	}, username)
	c.SetCookie("auth", QueryState, 0, "/", realMap["Host"], realMap["Proto"] == "https", true)
	c.Redirect(http.StatusFound, "/")
	p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] Login User: %s", ConnectionID, username))
} // ${redirect_path}

func (p *proxy) logoutHandler(c *gin.Context) {
	ConnectionID := random(8)
	realMap, err := p.getReal(c)
	if err != nil {
		p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] %s", ConnectionID, err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "400 Bad Request",
		})
		return
	}
	authCookie, err := c.Cookie("auth")
	if err == nil {
		if p.SessionLoginCache.Exist(authCookie) {
			_ = p.SessionLoginCache.Delete(authCookie)
		}
		c.SetCookie("auth", "", -1, "", realMap["Host"], realMap["Proto"] == "https", true)
	}
	if p.Config.AfterLogoutUri != "" {
		u := url.URL{}
		u.Scheme = realMap["Proto"]
		u.Host = realMap["HostWithPort"]
		u.Path = "/"
		c.Redirect(http.StatusFound, p.Config.AfterLogoutUri+"?target="+u.String())
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "200 Logout Success",
		})
		return
	}
}

func (p *proxy) defaultHandler(c *gin.Context) { // Any Path
	ConnectionID := random(8)
	realMap, err := p.getReal(c)
	if err != nil {
		p.Global.Logger.Println(clog.Info, fmt.Sprintf("[%s] %s", ConnectionID, err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "400 Bad Request",
		})
		return
	}
	authCookie, err := c.Cookie("auth")
	if err == nil {
		if p.SessionLoginCache.Exist(authCookie) {
			_ = p.SessionLoginCache.SetTTL(authCookie, SessionLoginDefaultExpiredTime)
			p.reverseProxy(c)
			return
		} else {
			c.SetCookie("auth", "", -1, "/", realMap["Host"], realMap["Proto"] == "https", true)
		}
	}
	u := url.URL{}
	u.Scheme = realMap["Proto"]
	u.Host = realMap["HostWithPort"]
	u.Path = p.Config.RedirectPath
	state := random(32)
	redirectQuery := url.Values{}
	redirectQuery.Set("response_type", "code")
	redirectQuery.Set("client_id", p.Config.ClientID)
	redirectQuery.Set("scope", strings.Join(p.Config.Scope, " "))
	redirectQuery.Set("redirect_uri", u.String())
	redirectQuery.Set("state", state)
	err = p.SessionCache.Set(cachemap.Config{
		Key:   state,
		Value: nil,
		TTL:   SessionDefaultExpiredTime,
	})
	c.Redirect(http.StatusFound, p.OpenidConfig.AuthorizationEndpoint+"?"+redirectQuery.Encode())
}

func (p *proxy) reverseProxy(c *gin.Context) {
	proxy := &httputil.ReverseProxy{}
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = p.Config.Upstream
		req.Header.Add("X-Proxy", "oidc")
	}
	proxy.ErrorLog = p.ReverseProxyLogger
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Write([]byte("502 Bad Gateway"))
		w.WriteHeader(http.StatusBadGateway)
	}
	proxy.ServeHTTP(c.Writer, c.Request)
}
