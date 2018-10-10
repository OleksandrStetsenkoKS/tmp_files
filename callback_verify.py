import base64
from urllib.parse import urlencode

from OpenSSL import crypto
from struct import pack, unpack

# data = {'amount': '0.99',
#         'authcode': '067610',
#         'created_dt': '2018-10-10T12:28:44+03:00',
#         'currency': 'RUB',
#         'description': '25700240390541',
#         'eci': '05',
#         'is3d': '0',
#         'merchant_order_id': '89023a3a8d2b4dfd814194b22fc2626b',
#         'message': 'Success',
#         'mpi_result': 'NONE',
#         'operation': 'authorize',
#         'operation_id': '36780366',
#         'order_id': 'vR0pOZXYG3St7alaJo1p_jqQlG0Z..000.201810',
#         'responsecode': '00',
#         'responsecodetext': 'Approved',
#         'rrn': '493290070299',
#         'signature': 'b881d0e5a887a17ed5ff90f43eefe516156b8e0612ff83c3baf6e7b4edff616fc5091cff0b9bbe4605ed47df068a8f2d49faa93891c79304521f9b5b699a3ee78f09b575da70f0b4a901eaf585cafcc8ac75d40065b051fa920bc17889e8c88542bd74362ccb274454fe46cfae4429409174271824713929e42bd8b48fdff7c5bf7360724ec4b26c0e35b8238a98ba378db562ae8b6468b045d34d9dbd61b229ffe5eceeda73fd5f40da2b69194a3133af6e9925cfdb529b717cb47e1fc7cf058da0201d8608a28574b8bb0e9bd3ad474be3fbe6afb584474d35fce5c29f31f58d93e5adfb807aec0005450ea5ed34fef16a06cedcfa76ca160c8966fc2e0abd',
#         'status': 'success',
#         'time': '2018-10-10T12:28:44+03:00'
#         }
# message = '&'.join([urlencode({k: data[k]}) for k in sorted(data.keys()) if k != 'signature'])
# signature = data['signature']

message = 'amount=216.17&authcode=509461&created_dt=2017-03-03T14%3A20%3A55%2B03%3A00&currency=RUB&description=2570030103349565&eci=07&is3d=0&merchant_order_id=120101302390317030300450063&message=Success&mpi_result=NONE&operation=authorize&operation_id=1733613282&order_id=0o2SGoypQUAcF7QJ3iMI4hkeT1kZ.01a3.201703&responsecode=00&responsecodetext=Approved&rrn=000580718410&status=success&time=2017-03-03T14%3A20%3A55%2B03%3A00'
signature = '3a818addb9005de963cc4558e9544854b47fb5034dfb2836bb285d1aea9e68fadf96d716b2490a7163800735f75e136069ed95e253f5157a06c26c4b2b1961c1b3990b1ab71d7cf99e9be804c3363bdf2b2a1e10aeac197e4893ee607ce4aeb661a44531983e5b53ad5d0a22cc161c974580b7ccdf97ef8e6b4158c51c26e87bede2108f597b370387dab396e1404a223337d1486351bb073498e40c348552caf34294cc6d59fae3d92dfa182e15f331221618d7b5a037fafc0b3ebbaf1bd9b87785e7434862f6c5211b77ebe485ee9a3b3bab630bc24e5ae3ca9f869fa4ecf60a19e9eb3cb4bba9b74883a32a7f03c38cd52eb701028c196b2590c8305277b7'


# Пример кода от YM на PHP: https://redmine.first-icard.com/issues/22#note-66


def sign_verify_own_cert():
    crt_bin = open('/home/stetsenko/ksolutions/firstcard/core/certs/yandexmoney/Piastrix.cer', "rb").read()
    pkey = open('/home/stetsenko/ksolutions/firstcard/core/certs/yandexmoney/ym_private.key.insecure', "rb").read()
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey)
    sgn = crypto.sign(pkey, message, 'sha1')
    sign = base64.b64encode(sgn).decode('utf-8')
    print(sign)
    # строка схожа с той, что signature
    print(signature)
    crt = crypto.load_certificate(crypto.FILETYPE_PEM, crt_bin)

    # аналог к openssl_verify, взято с http://www.php2python.com/wiki/function.openssl-verify/
    # если not verify - бросит ошибку
    crypto.verify(crt, base64.b64decode(sign.encode('utf-8')), message, 'sha1')


def verify_ym_sign():
    crt_bin = open('/home/stetsenko/ksolutions/firstcard/core/certs/yandexmoney/demo-scrat-2018.cer', "rb").read()
    crt = crypto.load_certificate(crypto.FILETYPE_PEM, crt_bin)

    # попытка сделать как это: $binarySign = pack("H*", $sign);
    sign = unpack('B' * len(signature.encode()), signature.encode())
    crypto.verify(crt, sign, message, 'sha1')


if __name__ == '__main__':
    sign_verify_own_cert()
