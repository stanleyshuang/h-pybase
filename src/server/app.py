# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
import base64
import hashlib
import hmac
import json
import time

import os
from flask import Flask, request, abort
from linebot import (
    LineBotApi, WebhookHandler
)
from linebot.exceptions import (
    InvalidSignatureError
)
from linebot.models import (
    MessageEvent, TextMessage, TextSendMessage,
)

from . import app



def base64url_decode(target):
    rem = len(target) % 4
    if rem > 0:
        target += '=' * (4 - rem)

    return base64.urlsafe_b64decode(target)


def check_signature(key, target, signature):
    calc_signature = hmac.new(
        key.encode('utf-8'),
        target.encode('utf-8'),
        hashlib.sha256
    ).digest()

    return hmac.compare_digest(signature, calc_signature)


def decode_id_token(id_token, channel_id, channel_secret, nonce=None):
    # step 1
    header, payload, signature = id_token.split('.')

    # step 2
    header_decoded = base64url_decode(header)
    payload_decoded = base64url_decode(payload)
    signature_decoded = base64url_decode(signature)

    # step 3
    valid_signature = check_signature(channel_secret,
                                      header + '.' + payload,
                                      signature_decoded)
    if not valid_signature:
        raise RuntimeError('invalid signature')

    payload_json = json.loads(payload_decoded.decode('utf-8'))

    # step 4
    if payload_json.get('iss') != 'https://access.line.me':
        raise RuntimeError('invalid iss')

    # step 5
    if payload_json.get('aud') != channel_id:
        raise RuntimeError('invalid aud')

    # step 6
    if int(time.time()) > payload_json.get('exp'):
        raise RuntimeError('invalid exp')

    # step 7 (Optional. But strongly recommended)
    if nonce is not None:
        if payload_json.get('nonce') != nonce:
            raise RuntimeError('invalid nonce')

    return payload_json
    


line_bot_api = LineBotApi(os.environ.get('LINE_MSG_CHANNEL_ACCESS_TOKEN', None))
handler = WebhookHandler(os.environ.get('LINE_MSG_CHANNEL_SECRET', None))


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    line_bot_api.reply_message(
        event.reply_token,
        TextSendMessage(text=event.message.text))

# Set up the index route
@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route("/callback", methods=['POST'])
def callback():
    # get X-Line-Signature header value
    signature = request.headers['X-Line-Signature']

    # get request body as text
    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)

    # handle webhook body
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        print("Invalid signature. Please check your channel access token/channel secret.")
        abort(400)

    return 'OK'


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
