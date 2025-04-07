package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/common"
	nhplog "github.com/OpenNHP/opennhp/log"
	"github.com/OpenNHP/opennhp/plugins"
	"github.com/OpenNHP/opennhp/utils"
	"github.com/gin-gonic/gin"
	"github.com/pelletier/go-toml/v2"
)

var (
	// 专有钉钉授权
	zyddAccessTokenCacheExpireTime = 7200 - 50
	zyddServerBaseUrl              = "https://openplatform.dg-work.cn"
	zyddLoginBaseUrl               = "https://login.dg-work.cn"
	zyddGetAccessTokenApi          = "/gettoken.json"
	zyddGetUserInfoApi             = "/rpc/oauth2/dingtalk_app_user.json"
	zyddGetUserInfoByCodeApi       = "/rpc/oauth2/getuserinfo_bycode.json"
)

type config struct {
	Placeholder string
}

var (
	log           *nhplog.Logger
	pluginDirPath string
	hostname      string
	localIp       string
	localMac      string
)

var (
	name    = "zydd"
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

type ZYDDAccessTokenResp struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg"`
	Content  struct {
		Data struct {
			ExpiresIn   int    `json:"expiresIn"`
			AccessToken string `json:"accessToken"`
		} `json:"data"`
		Success         bool   `json:"success"`
		RequestId       string `json:"requestId"`
		ResponseMessage string `json:"responseMessage"`
		ResponseCode    string `json:"responseCode"`
		BizErrorCode    string `json:"bizErrorCode"`
	} `json:"content"`
}

type ZYDDUserInfoResp struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg"`
	Content  struct {
		Data            any    `json:"data"`
		Success         bool   `json:"success"`
		RequestId       string `json:"requestId"`
		ResponseMessage string `json:"responseMessage"`
		ResponseCode    string `json:"responseCode"`
		BizErrorCode    string `json:"bizErrorCode"`
	} `json:"content"`
}

func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func Signature() string {
	return ""
}

func ExportedData() *plugins.PluginParamsOut {
	return &plugins.PluginParamsOut{}
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

	// backwards compatibility
	if len(resId) == 0 && len(req.ResourceId) > 0 {
		resId = req.ResourceId
		action = "valid"
	}

	switch {
	case strings.EqualFold(action, "valid"):
		ackMsg, err = authRegular(ctx, req, res, helper)

	case strings.EqualFold(action, "login"):
		ackMsg, err = authAndShowLogin(ctx, req, res, helper)

	case strings.EqualFold(action, "redirect"):
		ackMsg, err = authAndRedirect(ctx, req, res, helper)

	default:
		ackMsg = nil
		err = fmt.Errorf("action invalid")
	}
	return
}

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("helper is null")
	}

	req.Token = ctx.Query("token")
	req.Code = ctx.Query("code")
	if len(req.Token) == 0 && len(req.Code) == 0 {
		log.Error("no token or code provided")
		ctx.String(http.StatusOK, "{\"errMsg\": \"no token or code provided\"}")
		return nil, fmt.Errorf("no token or code provided")
	}
	qrLoginMode := false

	if len(req.Token) > 0 {
		// token verification mode
		accessToken, err := getZYDDAccessToken(res.AppKey, res.AppSecret, localIp, localMac)
		if err != nil {
			log.Error("get zydd access token failed: %v", err)
			ctx.String(http.StatusOK, "{\"errMsg\": \"get access token failed: %v\"}", err)
			return nil, err
		}

		log.Info("Get zydd access token %s successful", accessToken)
		resp, err := zyddGetUserInfo(accessToken, req.Token, res.AppKey, res.AppSecret, localIp, localMac)
		if err != nil {
			log.Error("get zydd user info failed: %v\nResponse: %s", err, resp)
			ctx.String(http.StatusOK, "{\"errMsg\": \"knock unauthorized: %v\"}", err)
			return nil, err
		}

		log.Info("Get zydd user info successful. Knock")
	} else if len(req.Code) > 0 {
		// qrcode login mode
		if res.ExInfo == nil {
			log.Error("extra login info not available")
			ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
			return nil, fmt.Errorf("extra login info not available")
		}
		qrLoginMode = true
		accessToken, err := getZYDDAccessToken(res.ExInfo["LoginAppKey"].(string), res.ExInfo["LoginAppSecret"].(string), localIp, localMac)
		if err != nil {
			log.Error("get zydd access token failed: %v", err)
			ctx.String(http.StatusOK, "{\"errMsg\": \"get access token failed: %v\"}", err)
			return nil, err
		}

		log.Info("Get zydd access token %s successful", accessToken)
		resp, err := zyddGetUserInfoByCode(accessToken, req.Code, res.ExInfo["LoginAppKey"].(string), res.ExInfo["LoginAppSecret"].(string), localIp, localMac)
		if err != nil {
			log.Error("get zydd user info by code failed: %v\nResponse: %s", err, resp)
			ctx.String(http.StatusOK, "{\"errMsg\": \"knock unauthorized: %v\"}", err)
			return nil, err
		}

		log.Info("Get zydd user info by code successful. Knock")
	}

	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)

	if ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("knock failed. %v", ackMsg.ErrMsg)
		ctx.String(http.StatusOK, "{\"errMsg\": \"knock failed: %v\"}", ackMsg.ErrMsg)
		return nil, err
	}
	if qrLoginMode {
		if res.ExInfo["RedirectWithParams"].(bool) {
			ackMsg.RedirectUrl = res.ExInfo["LoginRedirectUrl"].(string) + "?" + req.Url.RawQuery
		} else {
			ackMsg.RedirectUrl = res.ExInfo["LoginRedirectUrl"].(string)
		}
	}
	ackMsg.ErrMsg = ""
	log.Info("knock succeeded.")
	// assign the redirect url to the ackMsg
	if len(res.RedirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	} else {
		ackMsg.RedirectUrl = res.RedirectUrl
	}

	ctx.JSON(http.StatusOK, ackMsg)

	return ackMsg, nil
}

func makeZYDDHeader(apiUrl, rawQuery, appKey, appSecret, clientIp, clientMac string) map[string]string {
	t := time.Now()
	var timestamp = t.Format("2006-01-02T15:04:05.999-07:00")
	var nonce = fmt.Sprintf("%d%.4d", t.UnixMilli(), utils.RandNumber())
	var sign = fmt.Sprintf("%s\n%s\n%s\n%s\n%s", "POST", timestamp, nonce, apiUrl, rawQuery)
	var signKey = utils.Base64(utils.HMACSha256(appSecret, sign))

	headers := make(map[string]string)
	headers["X-Hmac-Auth-IP"] = clientIp
	headers["X-Hmac-Auth-MAC"] = clientMac
	headers["X-Hmac-Auth-Timestamp"] = timestamp
	headers["X-Hmac-Auth-Version"] = "1.0"
	headers["X-Hmac-Auth-Nonce"] = nonce
	headers["apiKey"] = appKey
	headers["X-Hmac-Auth-Signature"] = signKey

	return headers
}

func getZYDDAccessToken(appKey, appSecret, clientIp, clientMac string) (string, error) {
	accessToken := utils.CacheReadValue(utils.FormatCacheKey("zydd", appKey, "access_token"))
	if len(accessToken) > 0 {
		return accessToken, nil
	}

	params := url.Values{}
	params.Add("appkey", appKey)
	params.Add("appsecret", appSecret)
	rawQuery := params.Encode()
	u := zyddServerBaseUrl + zyddGetAccessTokenApi
	headers := makeZYDDHeader(zyddGetAccessTokenApi, rawQuery, appKey, appSecret, clientIp, clientMac)

	log.Info("[getZYDDAccessToken] posting to %s with\nheader: %+v\nbody: %s", u, headers, rawQuery)
	resp, err := utils.Request(u, "POST", rawQuery, headers)
	if err != nil {
		return resp, err
	}
	log.Info("[getZYDDAccessToken] response: %s", resp)

	d := &ZYDDAccessTokenResp{}
	if err = json.Unmarshal([]byte(resp), &d); err != nil {
		return resp, nil
	}

	if !d.Success || !d.Content.Success {
		if len(d.Content.ResponseMessage) == 0 {
			return resp, fmt.Errorf(d.ErrorMsg)
		}
		return resp, fmt.Errorf(d.Content.ResponseMessage)
	}

	utils.CacheWriteValue(utils.FormatCacheKey("zydd", appKey, "access_token"), d.Content.Data.AccessToken, zyddAccessTokenCacheExpireTime)
	return d.Content.Data.AccessToken, nil
}

func zyddGetUserInfo(accessToken, authCode, appKey, appSecret, clientIp, clientMac string) (string, error) {
	params := url.Values{}
	params.Add("access_token", accessToken)
	params.Add("auth_code", authCode)
	rawQuery := params.Encode()
	u := zyddServerBaseUrl + zyddGetUserInfoApi
	headers := makeZYDDHeader(zyddGetUserInfoApi, rawQuery, appKey, appSecret, clientIp, clientMac)

	log.Info("[zyddGetUserInfo] posting to %s with\nheader %+v\nbody: %s", u, headers, rawQuery)
	resp, err := utils.Request(u, "POST", rawQuery, headers)
	if err != nil {
		return "", err
	}
	log.Info("[zyddGetUserInfo] response: %s", resp)

	d := &ZYDDUserInfoResp{}
	if err = json.Unmarshal([]byte(resp), d); err != nil {
		return resp, err
	}

	if !d.Success || !d.Content.Success {
		if len(d.Content.ResponseMessage) == 0 {
			return resp, fmt.Errorf(d.ErrorMsg)
		}
		return resp, fmt.Errorf(d.Content.ResponseMessage)
	}

	return resp, nil
}

func zyddGetUserInfoByCode(accessToken, code, appKey, appSecret, clientIp, clientMac string) (string, error) {
	params := url.Values{}
	params.Add("access_token", accessToken)
	params.Add("code", code)
	rawQuery := params.Encode()
	u := zyddServerBaseUrl + zyddGetUserInfoByCodeApi
	headers := makeZYDDHeader(zyddGetUserInfoByCodeApi, rawQuery, appKey, appSecret, clientIp, clientMac)

	log.Info("[zyddGetUserInfoByCode] posting to %s with\nheader %+v\nbody: %s", u, headers, rawQuery)
	resp, err := utils.Request(u, "POST", rawQuery, headers)
	if err != nil {
		return "", err
	}
	log.Info("[zyddGetUserInfoByCode] response: %s", resp)

	d := &ZYDDUserInfoResp{}
	if err = json.Unmarshal([]byte(resp), d); err != nil {
		return resp, err
	}

	if !d.Success || !d.Content.Success {
		if len(d.Content.ResponseMessage) == 0 {
			return resp, fmt.Errorf(d.ErrorMsg)
		}
		return resp, fmt.Errorf(d.Content.ResponseMessage)
	}

	return resp, nil
}

func authAndShowLogin(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
		return nil, fmt.Errorf("extra login info not available")
	}

	ctx.HTML(http.StatusOK, "zydd/zydd_login.html", gin.H{
		"title":     res.ExInfo["Title"].(string),
		"clientId":  res.ExInfo["ClientId"].(string),
		"nhpServer": hostname,
		"aspId":     req.AuthServiceId,
		"resId":     res.ResourceId,
		"exInfo":    res.ExInfo,
	})

	return nil, nil
}

func authAndRedirect(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("helper is null")
	}

	ctx.HTML(http.StatusOK, "zydd/zydd_redirect.html", gin.H{
		"title":     res.ExInfo["Title"].(string),
		"clientId":  res.ExInfo["ClientId"].(string),
		"nhpServer": hostname,
		"aspId":     req.AuthServiceId,
		"resId":     res.ResourceId,
		"exInfo":    res.ExInfo,
	})

	return nil, nil
}

func main() {
	pluginDirPath = "E:\\work\\project\\opennhp-main\\opennhp-main\\server\\plugins\\zydd\\"
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

	resId := "mini-app-demo"
	action := "login"
	if len(resId) > 0 && strings.Contains(resId, "|") {
		params := strings.Split(resId, "|")
		resId = params[0]
		if len(params) > 1 {
			action = params[1]
		}
	}

	res := findResource(resId)
	if res == nil || len(res.Resources) == 0 {

		fmt.Printf("res nil")
	}
	fmt.Printf("action:" + action)
}
