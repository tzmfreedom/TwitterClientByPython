# coding: UTF-8

import urllib.request
import const
import json
import sys
import base64
import hmac
import hashlib
import random
import time
import webbrowser

#設定ファイルの読み込み
config_file = open("config.json")
config_data = json.load(config_file)
config_file.close()

const.KEY = config_data["consumer_key"]
const.SECRET = config_data["consumer_secret"]
const.SIGNATURE_METHOD = "HMAC-SHA1"
const.REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
const.AUTHENTICATE_URL = "https://api.twitter.com/oauth/authenticate"
const.AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize"
const.ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
const.ACCOUNT_SETTING_URL = "https://api.twitter.com/1.1/account/settings.json"
const.USER_TIMELINE_URL = "https://api.twitter.com/1.1/statuses/user_timeline.json"
const.HOME_TIMELINE_URL = "https://api.twitter.com/1.1/statuses/home_timeline.json"
const.TWEET_DELETE_URL = "https://api.twitter.com/1.1/statuses/destroy/{id}.json"
const.GET = "GET"
const.POST = "POST"


def createSignature(is_get, request_url, paramMap, token_secret):
    """
    Signatureを生成する
    """
    signature_key = const.SECRET + "&" + token_secret
    
    query = ""
    for key in sorted(paramMap.keys()):
        query += key + "=" + urllib.parse.quote(paramMap[key], '') + "&"
    
    query = query[0:len(query)-1]

    #query = urllib.parse.urlencode(paramMap)
    
    method = const.GET if is_get else const.POST
    signature_seed = (urllib.parse.quote(method, '') + "&" +
        urllib.parse.quote(request_url, '') + "&" + urllib.parse.quote(query, '')
        )
    digest_maker = hmac.new(signature_key.encode(), signature_seed.encode(), hashlib.sha1)
    return base64.b64encode(digest_maker.digest())

def getAccessToken():
    """
        認証URLを生成する
    """
    
    """
    RequestTokenを取得する
    """
    def getRequestToken():
        request_param = {}
        request_param["oauth_callback"] = "oob"
        request_param["oauth_consumer_key"] = const.KEY
        request_param["oauth_nonce"] = str(random.getrandbits(64))
        request_param["oauth_signature_method"] = const.SIGNATURE_METHOD
        request_param["oauth_timestamp"] = str(int(time.time()))
        request_param["oauth_version"] = "1.0"
        request_param["oauth_signature"] = createSignature(False, const.REQUEST_TOKEN_URL, request_param, '')
        
        req_for_req_token = urllib.request.Request(url=const.REQUEST_TOKEN_URL, data=urllib.parse.urlencode(request_param).encode())
        res_for_req_token = urllib.request.urlopen(req_for_req_token)
        return urllib.parse.parse_qs(res_for_req_token.read().decode("utf-8"))
    
    """
    AccessTokenを取得する
    """
    def getAccessToken():
        access_param = {}
        access_param["oauth_consumer_key"] = const.KEY
        access_param["oauth_nonce"] = str(random.getrandbits(64))
        access_param["oauth_signature_method"] = const.SIGNATURE_METHOD
        access_param["oauth_timestamp"] = str(int(time.time()))
        access_param["oauth_token"] = resmap_for_reqtoken["oauth_token"][0]
        access_param["oauth_version"] = "1.0"
        access_param["oauth_verifier"] = pin_code
        access_param["oauth_signature"] = createSignature(False, const.ACCESS_TOKEN_URL, access_param, resmap_for_reqtoken["oauth_token_secret"][0])
        
        req_for_accesstoken = urllib.request.Request(url=const.ACCESS_TOKEN_URL, data=urllib.parse.urlencode(access_param).encode())
        res_for_accesstoken = urllib.request.urlopen(req_for_accesstoken)
        
        return res_for_accesstoken.read().decode("utf-8")
    
    resmap_for_reqtoken = getRequestToken()
    webbrowser.open(const.AUTHENTICATE_URL + "?oauth_token=" + resmap_for_reqtoken["oauth_token"][0])
    pin_code = input('input PIN code')
    resmap_for_accesstoken = urllib.parse.parse_qs(getAccessToken())
    ret_json = json.dumps({
        "oauth_token" : resmap_for_accesstoken["oauth_token"][0], 
        "oauth_token_secret" : resmap_for_accesstoken["oauth_token_secret"][0],
        "user_id" : resmap_for_accesstoken["user_id"][0],
        "screen_name" : resmap_for_accesstoken["screen_name"][0]
    })
    return ret_json
            
args = sys.argv

if len(args) == 1:
    exit()

#OAuth認証
if args[1] == "-a":
    output_file = open("./token.json", "w");
    output_file.write(getAccessToken())
    output_file.close()
#自分のツイートをjson形式で出力
elif args[1] == "-o":
    #ファイルから設定情報を読み込み
    token_file = json.load(sys.stdin)
    access_token = token_file["oauth_token"]
    access_token_secret = token_file["oauth_token_secret"]
    user_id = token_file["user_id"]
    screen_name = token_file["screen_name"]
    
    def outputTweet():
        cnt = 0;
        min_id = None
        while True:
            url = const.USER_TIMELINE_URL
            apiParamMap = {}
            apiParamMap["oauth_consumer_key"] = const.KEY
            apiParamMap["oauth_nonce"] = str(random.getrandbits(64))
            apiParamMap["oauth_signature_method"] = const.SIGNATURE_METHOD
            apiParamMap["oauth_timestamp"] = str(int(time.time()))
            apiParamMap["oauth_version"] = "1.0"
            apiParamMap["oauth_token"] = access_token
            apiParamMap["user_id"] = user_id
            apiParamMap["count"] = "200"
            apiParamMap["trim_user"] = "true"
            if min_id is not None:
                min_id -= 1
                apiParamMap["max_id"] = str(min_id)
            apiParamMap["oauth_signature"] = createSignature(True, url, apiParamMap, access_token_secret)
            
            req = urllib.request.Request(url=url+'?'+urllib.parse.urlencode(apiParamMap))
            res = urllib.request.urlopen(req)
            retJson = res.read().decode("utf-8")
            
            json_decoder = json.JSONDecoder()
            
            #ツイートが存在しなければ処理を抜ける
            if len(json_decoder.decode(retJson)) == 0:
                break
            
            #ファイル出力
            out_file = open("out_%05d.json" % cnt, "w")
            out_file.write(retJson)
            
            #次のツイートを取得するために上限のIDを設定する
            for one_tweet in json_decoder.decode(retJson):
                if min_id is None:
                    min_id = one_tweet["id"]
                elif one_tweet["id"] < min_id:
                    min_id = one_tweet["id"]
            cnt += 1;
    outputTweet()
#指定したjsonをもとにツイートを削除する
elif args[1] == "-d":
    #ToDo: stdinどうする？
    token_fp = open("token.json", "r")
    token_file = json.load(token_fp)
    token_fp.close()
    access_token = token_file["oauth_token"]
    access_token_secret = token_file["oauth_token_secret"]
    user_id = token_file["user_id"]
    screen_name = token_file["screen_name"]
    
    cnt = 0
    for deleteline in json.load(sys.stdin):
        url = const.TWEET_DELETE_URL.replace("{id}", str(deleteline["id"]))
        apiParamMap = {}
        apiParamMap["oauth_consumer_key"] = const.KEY
        apiParamMap["oauth_nonce"] = str(random.getrandbits(64))
        apiParamMap["oauth_signature_method"] = const.SIGNATURE_METHOD
        apiParamMap["oauth_timestamp"] = str(int(time.time()))
        apiParamMap["oauth_version"] = "1.0"
        apiParamMap["oauth_token"] = access_token
        apiParamMap["trim_user"] = "true"
        apiParamMap["oauth_signature"] = createSignature(False, url, apiParamMap, access_token_secret)
        
        req = urllib.request.Request(url=url, data=urllib.parse.urlencode(apiParamMap).encode())
        res = urllib.request.urlopen(req)
        retJson = res.read().decode("utf-8")
        
        outfile = open("delete_backup.json" % cnt, "a")
        outfile.write(retJson)
        outfile.close()
        cnt += 1;