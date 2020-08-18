# -*- coding: utf-8 -*-

import os
import re
import hmac
import json
import uuid
import base64
import urllib
import hashlib
import logging
import requests
import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REQUEST_URL = 'https://alidns.aliyuncs.com/'
LAST_IP = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ip.txt')
SETTINGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aliyun_settings.json')


def get_common_params(settings):
    '''
    获取公共参数
    参考文档：https://help.aliyun.com/document_detail/29745.html?spm=5176.doc29776.6.588.sYhLJ0
    '''
    return {
        'Format': 'json',
        'Version': '2015-01-09',
        'AccessKeyId': settings['access_key'],
        'SignatureMethod': 'HMAC-SHA1',
        'Timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'SignatureVersion': '1.0',
        'SignatureNonce': uuid.uuid4()
    }


def get_signed_params(http_method, params, settings):
    '''
    参考文档：https://help.aliyun.com/document_detail/29747.html?spm=5176.doc29745.2.1.V2tmbU
    '''
    #1、合并参数，不包括Signature
    params.update(get_common_params(settings))
    #2、按照参数的字典顺序排序
    sorted_params = sorted(params.items())
    #3、encode 参数
    query_params = urllib.parse.urlencode(sorted_params)
    #4、构造需要签名的字符串
    str_to_sign = http_method + '&' + urllib.parse.quote_plus('/') + '&' + urllib.parse.quote_plus(query_params)
    #5、计算签名
    signature = hmac.new((settings['access_secret'] + '&').encode('utf-8'), (str_to_sign).encode('utf-8'), hashlib.sha1).digest()
    signature = base64.b64encode(signature).decode()
    #6、将签名加入参数中
    params['Signature'] = signature
    return params


def update_resolution(ip):
    '''
    修改云解析
    参考文档：
        获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
        修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
    '''
    with open(SETTINGS, 'r') as f:
        settings = json.loads(f.read())

    domain = settings['domain']
    root_domain = '.'.join(domain.split('.')[1:])
    pre_domain = domain.split('.')[0]

    #首先获取解析列表
    get_params = get_signed_params('GET', {
        'Action': 'DescribeDomainRecords',
        'DomainName': root_domain,
        #'TypeKeyWord': 'A'
    }, settings)
    logging.info('get current resolution params')
    get_resp = requests.get(REQUEST_URL, get_params)
    records = get_resp.json()
    if records.get('Message'):
        logging.error(records['Message'])
        exit()

    for record in records['DomainRecords']['Record']:
        if record['RR'] != pre_domain:
            continue
        logging.info('signed resolution params')
        post_params = get_signed_params('POST', {
            'Action': 'UpdateDomainRecord',
            'RecordId': record['RecordId'],
            'RR': record['RR'],
            'Type': record['Type'],
            'Value': ip
        }, settings)
        post_resp = requests.post(REQUEST_URL, post_params)
        result = post_resp.json()
        flag = "successfully" if not result.get('Message') else f'failed: {result["Message"]}'
        logging.info(f'update resolution {flag}')


def get_curr_ip():
    headers = {
        'Connection': 'keep-alive',
        'DNT': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'Accept-Language': 'zh,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7',
        'Cookie': 'BIDUPSID=9958FCCBD3691550DEA7EBEE55351347; PSTM=1595468073; BAIDUID=9958FCCBD369155085759244B505E510:FG=1; BDUSS=GE0M0FVZDFKbVJ6OTNVb05Bc1RaUnJCNlBicmY4QTNmekl6VDhuV0M1cWZka0JmSVFBQUFBJCQAAAAAAAAAAAEAAADCAE1KTXlzdGVyaW91c19MUgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ~pGF-f6RhfM; H_WISE_SIDS=150845_150585_152056_150073_147091_141744_150084_148867_150798_150913_147280_151796_150036_150166_151598_151017_151558_147890_146574_148523_127969_148796_146550_149719_146652_150345_146732_150964_151831_131423_152021_151388_150225_144659_147528_147912_145785_149251_150230_151268_146396_144966_139884_150340_151190_147546_148869_151704_110085; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; BDSFRCVID=Iu8OJexroG3_idOrKpEprZWtWeKKHJQTDYLE3ONZ67Yl5X-VN4vIEG0PtjcEHMA-2ZlgogKK0gOTH6KF_2uxOjjg8UtVJeC6EG0Ptf8g0M5; H_BDCLCKID_SF=JJkO_D_atKvjDbTnMITHh-F-5fIX5-RLf25tVp7F54nKDp0RBPrfXnDUK-ojbqTUbNv-ahvdWfjxsMTsQjbcXlTBjnrQtlkLQe_JLqTN3KJmfbcnQf7YLDrXWxvM2-biWbRM2MbdJqvP_IoG2Mn8M4bb3qOpBtQmJeTxoUJ25DnJhhCGe4bK-TrLeH-Dtf5; delPer=0; BDUSS_BFESS=GE0M0FVZDFKbVJ6OTNVb05Bc1RaUnJCNlBicmY4QTNmekl6VDhuV0M1cWZka0JmSVFBQUFBJCQAAAAAAAAAAAEAAADCAE1KTXlzdGVyaW91c19MUgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ~pGF-f6RhfM; PSINO=7; BDRCVFR[feWj1Vr5u3D]=I67x6TjHwwYf0; H_PS_PSSID=32294_1434_31671_32359_31254_32352_32046_32394_32405_32429_32116_31639; BIDUPSID=767700D726476D09385B464D6208BF86; PSTM=1596177058; BAIDUID=767700D726476D0975CC602058186A99:FG=1; delPer=0; PSINO=6; BDPASSGATE=IlPT2AEptyoA_yiU4VKH3kIN8efjSvGAH34DSEppQ6OPfCaWmhH3BrUvWz0HSieXBDP6wZTXt0Nmlj8KXlVXa_EqnBsZolpManS5xNSCgsTtPsx17Qok_QCXGCE2sA8PbRhL-3MEF3VDMlMCpubxgewmcOqsxQNHafmI5EDCmMrs1TCG17r6nmatXYpfRHveYOeNwujDnF6DVF_cVPH6TS_FqSFICJs4vbaGa25u2QT5rkcXGurSRvAa1G8vJpFeXAio1fWU60ul269w5I1nVVIlokOY-qL6MnJZ; H_WISE_SIDS=152083_152521_150845_150585_152348_150686_152056_150073_147091_141744_150084_148867_150798_150746_147280_152309_150036_150166_152299_149812_151017_151558_152590_146574_148523_127969_148796_146550_149719_146652_150345_146732_145784_152741_151831_131423_152021_151388_144659_147528_107320_151583_149251_150907_152284_151268_144966_152273_139884_150340_152249_147546_148869_151704_110085; BDSVRTM=73; ysm=1847|11009; __bsi=12635992669277233594_00_11_R_N_98_0303_c02f_Y; BDSVRBFE=Go'
    }
    r = requests.get('https://m.baidu.com/s?wd=ip', headers=headers)
    ip = re.findall('"ip":"(.*?)"', r.text)[0]
    logging.info(f'get current ip  {ip}')
    return ip


def get_lastest_ip():
    if os.path.exists(LAST_IP):
        with open(LAST_IP, 'r') as f:
            ip = f.read()
        logging.info(f'get the last ip {ip}')
        return ip


if __name__ == '__main__':
    curr_ip = get_curr_ip()
    last_ip = get_lastest_ip()

    if curr_ip != last_ip:
        update_resolution(curr_ip)

        with open(LAST_IP, 'w') as f:
            f.write(curr_ip)
