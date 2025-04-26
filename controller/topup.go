package controller

import (
	"errors"
	"fmt"
	"github.com/go-pay/gopay"
	"github.com/go-pay/gopay/wechat"
	"github.com/go-pay/util"
	"log"
	"net/url"
	"one-api/common"
	"one-api/model"
	"one-api/service"
	"one-api/setting"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"github.com/shopspring/decimal"
)

type EpayRequest struct {
	Amount        int64  `json:"amount"`
	PaymentMethod string `json:"payment_method"`
	TopUpCode     string `json:"top_up_code"`
}

type PayRequest struct {
	Amount        int64  `json:"amount"`
	PaymentMethod string `json:"payment_method"`
	TopUpCode     string `json:"top_up_code"`
}

type AmountRequest struct {
	Amount    int64  `json:"amount"`
	TopUpCode string `json:"top_up_code"`
}

type WechatPayResp struct {
	ReturnCode string `json:"return_code"`
	ReturnMsg  string `json:"return_msg"`
	PrepayId   string `json:"prepay_id"`
	CodeUrl    string `json:"top_up_code"`
}

type WechatPayNotifyReq struct {
	ReturnCode    string `json:"return_code"`
	ReturnMsg     string `json:"return_msg"`
	TransactionId string `json:"transaction_id"`
	OutTradeNo    string `json:"out_trade_no"`
}

type WechatPayNotifyResp struct {
	ReturnCode string `json:"return_code"`
	ReturnMsg  string `json:"return_msg"`
}

// GetEpayClient 获取易支付客户端 by KevinSui 2024/12/26
func GetEpayClient() *epay.Client {
	if setting.PayAddress == "" || setting.EpayId == "" || setting.EpayKey == "" {
		return nil
	}
	withUrl, err := epay.NewClient(&epay.Config{
		PartnerID: setting.EpayId,
		Key:       setting.EpayKey,
	}, setting.PayAddress)
	if err != nil {
		return nil
	}
	return withUrl
}

// GetWechatPayClient 获取微信支付客户端 by KevinSui 2024/12/26
func GetWechatPayClient() *wechat.Client {
	// 初始化微信客户端
	//    appId：应用ID
	//    mchId：商户ID
	//    apiKey：API秘钥值
	//    isProd：是否是正式环境
	var epayId = setting.EpayId
	var appId string
	var mchId string
	var mchAPIv2Key = setting.EpayKey

	if strings.Contains(epayId, "|") {
		ids := strings.Split(epayId, "|")
		appId = ids[0]
		mchId = ids[1]
	} else {
		return nil
	}

	client := wechat.NewClient(appId, mchId, mchAPIv2Key, true)

	// 打开Debug开关，输出请求日志，默认关闭
	//client.DebugSwitch = gopay.DebugOn

	// 自定义配置http请求接收返回结果body大小，默认 10MB
	//client.SetBodySize() // 没有特殊需求，可忽略此配置

	// 设置国家：不设置默认 中国国内
	//    wechat.China：中国国内
	//    wechat.China2：中国国内备用
	//    wechat.SoutheastAsia：东南亚
	//    wechat.Other：其他国家
	//client.SetCountry(wechat.China)

	// 添加微信pem证书
	//client.AddCertPemFilePath()
	//client.AddCertPemFileContent()
	//或
	// 添加微信pkcs12证书
	//client.AddCertPkcs12FilePath()
	//client.AddCertPkcs12FileContent()

	return client
}

// WechatPrepay 微信支付 by KevinSui 2024/12/26
func WechatPrepay(c *gin.Context, tradeNo string, notifyUrl *url.URL, amount int64) (codeUrl string, data interface{}, payErr error) {
	client := GetWechatPayClient()
	if client == nil {
		return "", nil, errors.New("当前管理员未配置微信支付信息")
	}
	// 初始化 BodyMap
	bm := make(gopay.BodyMap)
	bm.Set("nonce_str", util.RandomString(32)).
		Set("body", "Native支付").
		Set("out_trade_no", tradeNo).
		Set("total_fee", amount).
		Set("spbill_create_ip", c.ClientIP()).
		Set("notify_url", notifyUrl).
		Set("trade_type", wechat.TradeType_Native).
		Set("device_info", "WEB").
		Set("sign_type", wechat.SignType_MD5)
	//.SetBodyMap("scene_info", func(bm gopay.BodyMap) {
	//	bm.SetBodyMap("h5_info", func(bm gopay.BodyMap) {
	//		bm.Set("type", "Wap")
	//		bm.Set("wap_url", "https://www.fmm.ink")
	//		bm.Set("wap_name", "H5测试支付")
	//	})
	//}) /*.Set("openid", "o0Df70H2Q0fY8JXh1aFPIRyOBgu8")*/
	wxRsp, err := client.UnifiedOrder(c, bm)

	if err != nil {
		return "", nil, errors.New("拉起微信支付失败")
	}

	wechatPayResp := WechatPayResp{
		ReturnCode: wxRsp.ReturnCode,
		ReturnMsg:  wxRsp.ReturnMsg,
		PrepayId:   wxRsp.PrepayId,
		CodeUrl:    wxRsp.CodeUrl,
	}

	codeUrl = wxRsp.CodeUrl
	data = wechatPayResp

	return codeUrl, data, payErr
}

// EpayPrepay 易支付 by KevinSui 2024/12/26
func EpayPrepay(tradeNo string, notifyUrl *url.URL, returnUrl *url.URL, payMoney float64, req PayRequest) (codeUrl string, data interface{}, payErr error) {
	var payType string
	if req.PaymentMethod == "zfb" {
		payType = "alipay"
	}
	if req.PaymentMethod == "wx" {
		req.PaymentMethod = "wxpay"
		payType = "wxpay"
	}

	client := GetEpayClient()
	if client == nil {
		return "", nil, errors.New("当前管理员未配置易支付信息")
	}
	uri, params, clientErr := client.Purchase(&epay.PurchaseArgs{
		Type:           payType,
		ServiceTradeNo: "A" + tradeNo,
		Name:           "B" + tradeNo,
		Money:          strconv.FormatFloat(payMoney, 'f', 2, 64),
		Device:         epay.PC,
		NotifyUrl:      notifyUrl,
		ReturnUrl:      returnUrl,
	})
	if clientErr != nil {
		return "", nil, errors.New("拉起易支付失败")
	}

	codeUrl = uri
	data = params

	return codeUrl, data, nil
}

func getPayMoney(amount int64, group string) float64 {
	dAmount := decimal.NewFromInt(amount)

	if !common.DisplayInCurrencyEnabled {
		dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
		dAmount = dAmount.Div(dQuotaPerUnit)
	}

	topupGroupRatio := common.GetTopupGroupRatio(group)
	if topupGroupRatio == 0 {
		topupGroupRatio = 1
	}

	dTopupGroupRatio := decimal.NewFromFloat(topupGroupRatio)
	dPrice := decimal.NewFromFloat(setting.Price)

	payMoney := dAmount.Mul(dPrice).Mul(dTopupGroupRatio)

	return payMoney.InexactFloat64()
}

func getMinTopup() int64 {
	minTopup := setting.MinTopUp
	if !common.DisplayInCurrencyEnabled {
		dMinTopup := decimal.NewFromInt(int64(minTopup))
		dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
		minTopup = int(dMinTopup.Mul(dQuotaPerUnit).IntPart())
	}
	return int64(minTopup)
}

// RequestPay 支付处理方法 by KevinSui 2024/12/24
func RequestPay(c *gin.Context) {
	var req PayRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "参数错误"})
		return
	}
	if req.Amount < getMinTopup() {
		c.JSON(200, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", getMinTopup())})
		return
	}

	id := c.GetInt("id")
	//user, _ := model.GetUserById(id, false)
	group, err := model.GetUserGroup(id, true)
	payMoney := getPayMoney(req.Amount, group)
	if payMoney < 0.01 {
		c.JSON(200, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}

	if setting.PayAddress == "" || setting.EpayId == "" || setting.EpayKey == "" {
		c.JSON(200, gin.H{"message": "error", "data": "当前管理员未配置支付信息"})
		return
	}

	var (
		//uri       string
		//params    map[string]string
		codeUrl string
		data    interface{}
		payErr  error
	)

	callBackAddress := service.GetCallbackAddress()
	returnUrl, _ := url.Parse(setting.ServerAddress + "/log")
	tradeNo := fmt.Sprintf("%s%d", common.GetRandomString(6), time.Now().Unix())

	if strings.Contains(setting.PayAddress, "weixin") { // 微信支付
		notifyUrl, _ := url.Parse(callBackAddress + "/api/user/wechatpay/notify")
		codeUrl, data, payErr = WechatPrepay(c, tradeNo, notifyUrl, int64(payMoney*100))
	} else { // 易支付
		notifyUrl, _ := url.Parse(callBackAddress + "/api/user/epay/notify")
		codeUrl, data, payErr = EpayPrepay(tradeNo, notifyUrl, returnUrl, payMoney, req)
	}

	if payErr != nil {
		c.JSON(200, gin.H{"message": "error", "data": payErr.Error()})
		return
	}

	amount := req.Amount
	if !common.DisplayInCurrencyEnabled {
		amount = amount / int64(common.QuotaPerUnit)
	}
	topUp := &model.TopUp{
		UserId:     id,
		Amount:     amount,
		Money:      payMoney,
		TradeNo:    "A" + tradeNo,
		CreateTime: time.Now().Unix(),
		Status:     "pending",
	}
	err = topUp.Insert()
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "创建订单失败"})
		return
	}
	c.JSON(200, gin.H{"message": "success", "data": data, "url": codeUrl})
}

// RequestEpay 废弃，改用RequestPay by KevinSui 2024/12/26
func RequestEpay(c *gin.Context) {
	var req EpayRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "参数错误"})
		return
	}
	if req.Amount < getMinTopup() {
		c.JSON(200, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", getMinTopup())})
		return
	}

	id := c.GetInt("id")
	group, err := model.GetUserGroup(id, true)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}
	payMoney := getPayMoney(req.Amount, group)
	if payMoney < 0.01 {
		c.JSON(200, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}
	payType := "wxpay"
	if req.PaymentMethod == "zfb" {
		payType = "alipay"
	}
	if req.PaymentMethod == "wx" {
		req.PaymentMethod = "wxpay"
		payType = "wxpay"
	}
	callBackAddress := service.GetCallbackAddress()
	returnUrl, _ := url.Parse(setting.ServerAddress + "/log")
	notifyUrl, _ := url.Parse(callBackAddress + "/api/user/epay/notify")
	tradeNo := fmt.Sprintf("%s%d", common.GetRandomString(6), time.Now().Unix())
	tradeNo = fmt.Sprintf("USR%dNO%s", id, tradeNo)
	client := GetEpayClient()
	if client == nil {
		c.JSON(200, gin.H{"message": "error", "data": "当前管理员未配置支付信息"})
		return
	}
	uri, params, err := client.Purchase(&epay.PurchaseArgs{
		Type:           payType,
		ServiceTradeNo: tradeNo,
		Name:           fmt.Sprintf("TUC%d", req.Amount),
		Money:          strconv.FormatFloat(payMoney, 'f', 2, 64),
		Device:         epay.PC,
		NotifyUrl:      notifyUrl,
		ReturnUrl:      returnUrl,
	})
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}
	amount := req.Amount
	if !common.DisplayInCurrencyEnabled {
		dAmount := decimal.NewFromInt(int64(amount))
		dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
		amount = dAmount.Div(dQuotaPerUnit).IntPart()
	}
	topUp := &model.TopUp{
		UserId:     id,
		Amount:     amount,
		Money:      payMoney,
		TradeNo:    tradeNo,
		CreateTime: time.Now().Unix(),
		Status:     "pending",
	}
	err = topUp.Insert()
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "创建订单失败"})
		return
	}
	c.JSON(200, gin.H{"message": "success", "data": params, "url": uri})
}

// tradeNo lock
var orderLocks sync.Map
var createLock sync.Mutex

// LockOrder 尝试对给定订单号加锁
func LockOrder(tradeNo string) {
	lock, ok := orderLocks.Load(tradeNo)
	if !ok {
		createLock.Lock()
		defer createLock.Unlock()
		lock, ok = orderLocks.Load(tradeNo)
		if !ok {
			lock = new(sync.Mutex)
			orderLocks.Store(tradeNo, lock)
		}
	}
	lock.(*sync.Mutex).Lock()
}

// UnlockOrder 释放给定订单号的锁
func UnlockOrder(tradeNo string) {
	lock, ok := orderLocks.Load(tradeNo)
	if ok {
		lock.(*sync.Mutex).Unlock()
	}
}

func EpayNotify(c *gin.Context) {
	params := lo.Reduce(lo.Keys(c.Request.URL.Query()), func(r map[string]string, t string, i int) map[string]string {
		r[t] = c.Request.URL.Query().Get(t)
		return r
	}, map[string]string{})
	client := GetEpayClient()
	if client == nil {
		log.Println("易支付回调失败 未找到配置信息")
		_, err := c.Writer.Write([]byte("fail"))
		if err != nil {
			log.Println("易支付回调写入失败")
			return
		}
	}
	verifyInfo, err := client.Verify(params)
	if err == nil && verifyInfo.VerifyStatus {
		_, err := c.Writer.Write([]byte("success"))
		if err != nil {
			log.Println("易支付回调写入失败")
		}
	} else {
		_, err := c.Writer.Write([]byte("fail"))
		if err != nil {
			log.Println("易支付回调写入失败")
		}
		log.Println("易支付回调签名验证失败")
		return
	}

	if verifyInfo.TradeStatus == epay.StatusTradeSuccess {
		log.Println(verifyInfo)
		LockOrder(verifyInfo.ServiceTradeNo)
		defer UnlockOrder(verifyInfo.ServiceTradeNo)
		topUp := model.GetTopUpByTradeNo(verifyInfo.ServiceTradeNo)
		if topUp == nil {
			log.Printf("易支付回调未找到订单: %v", verifyInfo)
			return
		}
		if topUp.Status == "pending" {
			topUp.Status = "success"
			err := topUp.Update()
			if err != nil {
				log.Printf("易支付回调更新订单失败: %v", topUp)
				return
			}
			//user, _ := model.GetUserById(topUp.UserId, false)
			//user.Quota += topUp.Amount * 500000
			dAmount := decimal.NewFromInt(int64(topUp.Amount))
			dQuotaPerUnit := decimal.NewFromFloat(common.QuotaPerUnit)
			quotaToAdd := int(dAmount.Mul(dQuotaPerUnit).IntPart())
			err = model.IncreaseUserQuota(topUp.UserId, quotaToAdd, true)
			if err != nil {
				log.Printf("易支付回调更新用户失败: %v", topUp)
				return
			}
			log.Printf("易支付回调更新用户成功 %v", topUp)
			model.RecordLog(topUp.UserId, model.LogTypeTopup, fmt.Sprintf("使用在线充值成功，充值金额: %v，支付金额：%f", common.LogQuota(quotaToAdd), topUp.Money))
		}
	} else {
		log.Printf("易支付异常回调: %v", verifyInfo)
	}
}

func WechatPayNotify(c *gin.Context) {
	// ====支付异步通知参数解析和验签Sign====
	// 解析支付异步通知的参数
	//    req：*http.Request
	//    ctx.Request   是 gin 框架的获取 *http.Request
	//    ctx.Request() 是 echo 框架的获取 *http.Request
	//    返回参数 notifyReq：通知的参数
	//    返回参数 err：错误信息
	notifyReq, err := wechat.ParseNotifyToBodyMap(c.Request)

	// 验签操作
	ok, err := wechat.VerifySign(setting.EpayKey, wechat.SignType_MD5, notifyReq)
	if !ok {
		log.Println("微信支付回调验签失败")
		if err != nil {
			wechatPayNotifyResp := WechatPayNotifyResp{
				ReturnCode: "FAIL",
				//ReturnMsg:  "签名验证失败",
				ReturnMsg: err.Error(),
			}
			c.JSON(200, wechatPayNotifyResp)
			return
		}
	}

	client := GetWechatPayClient()
	// 初始化参数结构体
	bm := make(gopay.BodyMap)
	var req WechatPayNotifyReq
	reqErr := c.ShouldBindJSON(&req)
	if reqErr != nil {
		log.Printf("微信支付回调参数获取失败 %v", err)
		wechatPayNotifyResp := WechatPayNotifyResp{
			ReturnCode: "FAIL",
			//ReturnMsg:  "签名验证失败",
			ReturnMsg: reqErr.Error(),
		}
		c.JSON(200, wechatPayNotifyResp)
		return
	}

	bm.Set("out_trade_no", req.OutTradeNo).
		Set("nonce_str", util.RandomString(32)).
		Set("sign_type", wechat.SignType_MD5)

	// 请求订单查询，成功后得到结果
	wxRsp, resBm, err := client.QueryOrder(c, bm)
	if err != nil {
		//xlog.Error(err)
		log.Printf("微信支付请求订单查询失败 %v", err)
		wechatPayNotifyResp := WechatPayNotifyResp{
			ReturnCode: "FAIL",
			//ReturnMsg:  "签名验证失败",
			ReturnMsg: err.Error(),
		}
		c.JSON(200, wechatPayNotifyResp)
		return
	}
	//xlog.Debug("wxRsp：", wxRsp)
	//xlog.Debug("resBm:", resBm)
	//log.Printf("wxRsp %v", wxRsp)
	//log.Printf("resBm %v", resBm)

	if wxRsp.ReturnCode == "SUCCESS" {
		log.Println(wxRsp)
		outTradeNo := wxRsp.OutTradeNo
		LockOrder(outTradeNo)
		defer UnlockOrder(outTradeNo)
		topUp := model.GetTopUpByTradeNo(outTradeNo)
		if topUp == nil {
			log.Printf("微信支付支付回调未找到订单: %v", wxRsp)
			wechatPayNotifyResp := WechatPayNotifyResp{
				ReturnCode: "FAIL",
				ReturnMsg:  "微信支付支付回调未找到订单",
			}
			c.JSON(200, wechatPayNotifyResp)
			return
		}
		if topUp.Status == "pending" {
			topUp.Status = "success"
			err := topUp.Update()
			if err != nil {
				log.Printf("微信支付回调更新订单失败: %v", topUp)
				wechatPayNotifyResp := WechatPayNotifyResp{
					ReturnCode: "FAIL",
					ReturnMsg:  "微信支付回调更新订单失败",
				}
				c.JSON(200, wechatPayNotifyResp)
				return
			}
			//user, _ := model.GetUserById(topUp.UserId, false)
			//user.Quota += topUp.Amount * 500000
			err = model.IncreaseUserQuota(topUp.UserId, int(topUp.Amount*int64(common.QuotaPerUnit)), true)
			if err != nil {
				log.Printf("微信支付回调更新用户失败: %v", topUp)
				wechatPayNotifyResp := WechatPayNotifyResp{
					ReturnCode: "FAIL",
					ReturnMsg:  "微信支付回调更新用户失败",
				}
				c.JSON(200, wechatPayNotifyResp)
				return
			}
			log.Printf("易支付回调更新用户成功 %v", topUp)
			model.RecordLog(topUp.UserId, model.LogTypeTopup, fmt.Sprintf("使用在线充值成功，充值金额: %v，支付金额：%f", common.LogQuota(int(topUp.Amount*int64(common.QuotaPerUnit))), topUp.Money))
			wechatPayNotifyResp := WechatPayNotifyResp{
				ReturnCode: "SUCCESS",
				ReturnMsg:  "微信支付回调成功返回",
			}
			c.JSON(200, wechatPayNotifyResp)
			return
		}
	} else {
		log.Printf("易支付异常回调: %v\n%v", wxRsp, resBm)
	}
}

func RequestAmount(c *gin.Context) {
	var req AmountRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "参数错误"})
		return
	}

	if req.Amount < getMinTopup() {
		c.JSON(200, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", getMinTopup())})
		return
	}
	id := c.GetInt("id")
	group, err := model.GetUserGroup(id, true)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}
	payMoney := getPayMoney(req.Amount, group)
	if payMoney <= 0.01 {
		c.JSON(200, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}
	c.JSON(200, gin.H{"message": "success", "data": strconv.FormatFloat(payMoney, 'f', 2, 64)})
}
