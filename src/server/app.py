# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  h-pybase ver. 1.0
# Date:     2021/02/12
#
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
