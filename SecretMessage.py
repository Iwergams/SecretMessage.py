from hikkatl import Client, events
from hikkatl.tl.types import Message
import re
import base64
import random
import string

class SecretMessagePlugin:
    def __init__(self, client: Client):
        self.client = client
        self.secret_messages = {}

    @events.message(events.NewMessage(outgoing=True, pattern=r'\.secret (.+?)\s*(\S+)?$'))
    async def send_secret_message(self, event: Message):
        message = event.message
        text = message.text.split(' ', 1)[1]
        args = text.split(' ', 1)
        content = args[0]
        key = args[1] if len(args) > 1 else self.generate_key(8)

        cipher = self.encrypt(content, key)
        cipher_text = base64.b64encode(cipher.encode()).decode()

        msg_id = str(random.randint(1000, 9999))
        self.secret_messages[msg_id] = {
            'content': cipher_text,
            'key': key,
            'owner': message.sender_id
        }

        await self.client.send_message(message.chat_id, f"Секретное сообщение: {msg_id}\nКлюч: {key}")

    @events.message(events.NewMessage(outgoing=True, pattern=r'\.decode (\S+)'))
    async def decode_message(self, event: Message):
        message = event.message
        key = message.text.split(' ', 1)[1]

        for msg_id, data in self.secret_messages.items():
            if data['key'] == key:
                cipher_text = data['content']
                decoded_cipher = base64.b64decode(cipher_text).decode()
                content = self.decrypt(decoded_cipher, key)
                await self.client.send_message(message.chat_id, f"Расшифрованное сообщение: {content}")
                return

        await self.client.send_message(message.chat_id, "Неверный ключ или сообщение не найдено.")

    @events.message(events.NewMessage(outgoing=True, pattern=r'\.update_key (\S+) (\S+)'))
    async def update_key(self, event: Message):
        message = event.message
        old_key = message.text.split(' ', 2)[1]
        new_key = message.text.split(' ', 2)[2]

        for msg_id, data in self.secret_messages.items():
            if data['key'] == old_key and data['owner'] == message.sender_id:
                data['key'] = new_key
                await self.client.send_message(message.chat_id, f"Ключ для сообщения {msg_id} обновлён.")
                return

        await self.client.send_message(message.chat_id, "Сообщение не найдено или у вас нет прав для изменения ключа.")

    def generate_key(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encrypt(self, text, key):
        cipher = []
        for i in range(len(text)):
            key_char = key[i % len(key)]
            cipher_char = chr(ord(text[i]) + ord(key_char))
            cipher.append(cipher_char)
        return ''.join(cipher)

    def decrypt(self, cipher, key):
        text = []
        for i in range(len(cipher)):
            key_char = key[i % len(key)]
            text_char = chr(ord(cipher[i]) - ord(key_char))
            text.append(text_char)
        return ''.join(text)
