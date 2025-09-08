package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	toml "github.com/pelletier/go-toml/v2"
)

type config struct {
	AUTH0_DOMAIN        string
	AUTH0_CLIENT_ID     string
	AUTH0_CLIENT_SECRET string
	AUTH0_CALLBACK_URL  string
}

var (
	// Example Plugin Settings
	log           *nhplog.Logger
	pluginDirPath string
	hostname      string
	localIp       string
	localMac      string
	oktaAuth      *Authenticator
)

var (
	name    = "okta"
	version = "0.1.1"

	baseConfigWatch io.Closer
	resConfigWatch  io.Closer

	baseConf         *config
	resourceMapMutex sync.Mutex
	resourceMap      common.ResourceGroupMap
)

var (
	errLoadConfig = fmt.Errorf("config load error")
)

func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func Init(in *plugins.PluginParamsIn) error {
	if in.PluginDirPath != nil {
		pluginDirPath = *in.PluginDirPath
	}
	if in.Log != nil {
		log = in.Log
	}
	if in.Hostname != nil {
		hostname = *in.Hostname
	}
	if in.LocalIp != nil {
		localIp = *in.LocalIp
	}
	if in.LocalMac != nil {
		localMac = *in.LocalMac
	}

	// load config
	fileNameBase := (filepath.Join(pluginDirPath, "etc", "config.toml"))
	if err := updateConfig(fileNameBase); err != nil {
		// ignore error
		_ = err
	}

	baseConfigWatch = utils.WatchFile(fileNameBase, func() {
		log.Info("base config: %s has been updated", fileNameBase)
		updateConfig(fileNameBase)
	})

	fileNameRes := filepath.Join(pluginDirPath, "etc", "resource.toml")
	if err := updateResource(fileNameRes); err != nil {
		// ignore error
		_ = err
	}
	resConfigWatch = utils.WatchFile(fileNameRes, func() {
		log.Info("resource config: %s has been updated", fileNameRes)
		updateResource(fileNameRes)
	})

	return nil
}

func updateConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
	}

	var conf config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}

	baseConf = &conf
	return err
}

func updateResource(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read resource config: %v", err)
	}

	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	resourceMap = make(common.ResourceGroupMap)
	if err := toml.Unmarshal(content, &resourceMap); err != nil {
		log.Error("failed to unmarshal resource config: %v", err)
	}

	// res is pointer so we can update its fields
	for resId, res := range resourceMap {
		res.AuthServiceId = name
		res.ResourceId = resId
	}

	return err
}

func Close() error {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}
	if resConfigWatch != nil {
		resConfigWatch.Close()
	}
	return nil
}

func findResource(resId string) *common.ResourceData {
	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	res, found := resourceMap[resId]
	if found {
		return res
	}
	return nil
}

func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	if helper == nil {
		return nil, fmt.Errorf("AuthWithHttp: helper is null")
	}

	resId := ctx.Query("resid")
	action := ctx.Query("action")
	if len(resId) > 0 && strings.Contains(resId, "|") {
		params := strings.Split(resId, "|")
		resId = params[0]
		if len(params) > 1 {
			action = params[1]
		}
	}

	res := findResource(resId)
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}

	corsMiddleware(ctx)

	switch {
	case strings.EqualFold(action, "valid"):
		ackMsg, err = authRegular(ctx, req, res, helper)

	case strings.EqualFold(action, "login"):
		authAndShowLogin(ctx)

	case strings.EqualFold(action, "oauth"):
		err = authOkta(ctx)

	default:
		ackMsg = nil
		err = fmt.Errorf("action invalid")
	}
	return
}

func authAndShowLogin(ctx *gin.Context) {
	session := sessions.Default(ctx)
	t := session.Get("oauth_token")
	oauthToken, ok1 := t.(oauth2.Token)
	s := session.Get("state")
	state, ok2 := s.(string)
	if ok1 && ok2 {
		_, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), &oauthToken)
		if err == nil {
			ctx.Redirect(http.StatusSeeOther, "/plugins/okta?resid=demo&action=valid"+"&state="+state)
			return
		}
	}

	ctx.HTML(http.StatusOK, "okta/auth0home.html", gin.H{})
}

func authOkta(ctx *gin.Context) error {
	var err error
	oktaAuth, err = NewAuthenticator(*baseConf)
	if err != nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"failed to initialize authenticator\"}")
		oktaAuth = nil
		return fmt.Errorf("failed to initialize authenticator")
	}

	err = oktaAuth.DoAuth(ctx)
	if err != nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"user authentication failed\"}")
		return fmt.Errorf("user authentication failed")
	}

	return nil
}

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if oktaAuth == nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"invalid authenticator\"}")
		return nil, fmt.Errorf("invalid authenticator")
	}

	session := sessions.Default(ctx)
	if ctx.Query("state") != session.Get("state") {
		ctx.String(http.StatusOK, "{\"errMsg\": \"invalid authentication session\"}")
		return nil, fmt.Errorf("invalid authentication session")
	}

	authorizeCode := ctx.Query("code")
	var err error
	var oktaToken *oauth2.Token

	if len(authorizeCode) > 0 {
		// when there is authorize code in query, it is a callback from okta
		// Exchange an authorization code for a token.
		oktaToken, err = oktaAuth.Exchange(ctx.Request.Context(), authorizeCode)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to convert an authorization code into a token\"}")
			return nil, fmt.Errorf("failed to convert an authorization code into a token")
		}

		idToken, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), oktaToken)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to verify ID token\"}")
			return nil, fmt.Errorf("failed to verify ID token")
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to claim user profile\"}")
			return nil, fmt.Errorf("failed to claim user profile")
		}

		session.Set("oauth_token", *oktaToken)
		session.Set("profile", profile)
		session.Save()
	} else {
		// if no authorize code exists, try extract the oauth token from the session
		oauthToken := session.Get("oauth_token")
		t, ok := oauthToken.(oauth2.Token)
		if !ok {
			ctx.String(http.StatusOK, "{\"errMsg\": \"invalid session paramete\"}")
			return nil, fmt.Errorf("invalid session parameter")
		}
		oktaToken = &t

		_, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), oktaToken)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to verify ID token\"}")
			session.Clear()
			ctx.Redirect(http.StatusSeeOther, "/plugins/okta?resid=demo&action=login")
			return nil, fmt.Errorf("failed to verify ID token")
		}
	}

	// interact with udp server for ac operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
	} else {
		log.Info("knock succeeded.")
		ackMsg.ErrMsg = ""
		// assign the redirect url to the ackMsg
		if len(res.RedirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		} else {
			ackMsg.RedirectUrl = res.RedirectUrl
		}

		// set cookies
		// note that a dot in domain prefix used to make a difference, but now it doesn't (RFC6265).
		// The cookie will be sent to any subdomain of the specified domain, with or without the leading dot.
		singleHost := len(ackMsg.ACTokens) == 1
		for resName, token := range ackMsg.ACTokens {
			if singleHost {
				ctx.SetCookie(
					"nhp-token",            // Name
					url.QueryEscape(token), // Value
					int(res.OpenTime),      // MaxAge - use the knock interval time
					"/",                    // Path
					res.CookieDomain,       // Domain
					true,                   // Secure - if true, this cookie will only be sent on https, not http
					true)                   // HttpOnly - if true, this cookie will only be sent on http(s)
			} else {
				domain := strings.Split(ackMsg.ResourceHost[resName], ":")[0]
				ctx.SetCookie(
					"nhp-token"+"/"+resName, // Name
					url.QueryEscape(token),  // Value
					int(res.OpenTime),       // MaxAge - use the knock interval time
					"/",                     // Path
					domain,                  // Domain
					true,                    // Secure - if true, this cookie will only be sent on https, not http
					true)                    // HttpOnly - if true, this cookie will only be sent on http(s)
			}
			log.Info("ctx.SetCookie.")
		}
	}
	ctx.JSON(http.StatusOK, ackMsg)
	return ackMsg, nil
}

func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	ackMsg = req.Ack
	if helper == nil {
		return ackMsg, fmt.Errorf("AuthWithNHP: helper is null")
	}

	var found bool
	var res *common.ResourceData
	resourceMapMutex.Lock()
	res, found = resourceMap[req.Msg.ResourceId]
	resourceMapMutex.Unlock()

	if !found || len(res.Resources) == 0 {
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// there is no backend auth in this plugin, fail the request if SkipAuth is false
	if !res.SkipAuth {
		err = common.ErrBackendAuthRequired
		ackMsg.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// skip backend auth and continue with AC operations
	log.Info("agent user [%s]: skip auth", req.Msg.UserId)
	ackMsg.OpenTime = res.OpenTime

	// PART III: request ac operation for each resource and block for response
	ackMsg, err = helper.AuthWithNhpCallbackFunc(req, res)

	return ackMsg, err
}

func corsMiddleware(ctx *gin.Context) {
	originResource := ctx.Request.Header.Get("Origin")

	if originResource != "" {
		// HTTP headers for CORS
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", originResource) // allow cross-origin resource sharing
	}

	ctx.Next()
}

func main() {

}
