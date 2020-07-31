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
        'TypeKeyWord': 'A'
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
        'Cookie': 'BIDUPSID=767700D726476D09385B464D6208BF86; PSTM=1596177058; BAIDUID=767700D726476D0975CC602058186A99:FG=1; H_WISE_SIDS=152083_152477_150724_152360_150685_149356_150076_147090_150085_151594_148867_150796_147279_152309_150043_149812_151017_146573_148523_151032_127969_148794_149719_146653_151319_146732_145784_152740_150437_131423_152023_151389_152696_147588_151147_107311_152560_152274_149253_151220_152284_144966_152270_152513_139883_146786_149771_152249_147546_148869_151704_110085; delPer=0; BDSVRTM=53; PSINO=6; ysm=1847; __bsi=9304608067065090910_00_24_N_N_84_0303_c02f_Y; BDSVRBFE=Go'
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
