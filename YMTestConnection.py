import uuid
from pprint import pprint

import requests

from utils import get_abs_path

CERTIFICATE_PATH = "/home/stetsenko/ksolutions/firstcard/core/certs/yandexmoney/"
acquirer_cert = "Piastrix.cer"
acquirer_cert_key = "ym_private.key.insecure"


def authorize():
    data = {
        "amount": 0.10,
        "currency": "RUB",
        "description": "test pay",
        "merchant_order_id": uuid.uuid4().hex,
        "client_ip": "173.65.34.137",

        "card_number": "4444444444444448",
        "expiration_year": "2019",
        "expiration_month": "06",
        "cvn": "000",
        "cardholder": "JOHN SMITH",

        "force_3ds": 1,
        "auto_clearing": 0,
        "authorized_timeout": 360,
        "authorize_timeout_action": "cancel",

        "notify_url": "https://hello.com/payment/notify",
        "success_url_3ds": "https://hello.com/payment/success",
        "fail_url_3ds": "https://hello.com/payment/failed",
    }
    data["payment_params"] = {"paymentLinkParams": {"shopId": 531189, "shopArticleId": 579836}}

    url = "https://demo-scrat.yamoney.ru:9094/gates/system/authorize"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    timeout = 5
    certs = (get_abs_path(CERTIFICATE_PATH, acquirer_cert),
             get_abs_path(CERTIFICATE_PATH, acquirer_cert_key))
    try:
        response = requests.post(url, data=data, headers=headers, timeout=timeout, cert=certs)
    except Exception as ex:
        print(ex)

    print('URL: ', url)
    print('Headers: ', headers)
    pprint(data)
    print("=" * 150)
    print(response.content)
    print("=" * 150)
    print(response.text)


if __name__ == "__main__":
    authorize()
