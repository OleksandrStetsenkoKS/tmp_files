import uuid

import requests

from utils import get_abs_path


CERTIFICATE_PATH = '/home/stetsenko/ksolutions/firstcard/core/certs/yandexmoney/'
acquirer_cert = 'Piastrix.cer'
acquirer_cert_key = 'ym_private.key.insecure'

def authorize():
    data = {
        'amount': 0.10,
        'currency': 'RUB',
        'description': 'test pay',
        'merchant_order_id': uuid.uuid4().hex,
        'client_ip': '173.65.34.137',

        'card_number': '5189010003000001',
        'expiration_year': '2019',
        'expiration_month': '08',
        'cvn': 546,
        'cardholder': 'JOHN SMITH',

        'force_3ds': 1,
        'auto_clearing': 0,
        'authorized_timeout': 360,
        'authorize_timeout_action': 'cancel',

        'notify_url': 'https://hello.com/payment/notify',
        'success_url_3ds': 'https://hello.com/payment/success',
        'fail_url_3ds': 'https://hello.com/payment/failed',
    }
    data['payment_params'] = {
        'paymentLinkParams': {'shopId': 2543,
                              'shopArticleId': 43256}
    }

    url = 'https://paymentcard.yamoney.ru:9094/gates/system/authorize'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    timeout = 5
    certs = (get_abs_path(CERTIFICATE_PATH, acquirer_cert),
             get_abs_path(CERTIFICATE_PATH, acquirer_cert_key))
    try:
        response = requests.post(url, data=data, headers=headers, timeout=timeout, cert=certs)
    except Exception as ex:
        print(ex)



if __name__ == '__main__':
    authorize()




#####
Exception
HTTPSConnectionPool(host='paymentcard.yamoney.ru', port=9094): Max retries exceeded with url: /gates/system/authorize (Caused by ConnectTimeoutError(<urllib3.connection.VerifiedHTTPSConnection object at 0x7f0c3020a978>, 'Connection to paymentcard.yamoney.ru timed out. (connect timeout=5)'))




