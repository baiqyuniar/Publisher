from Cryptodome.Cipher import AES
import binascii
from random import randint
from time import sleep
import paho.mqtt.client as mqtt

from decouple import config

#MQTT
mqttBroker = config('ADDRESS')
client = mqtt.Client("AES Publisher")
client.connect(mqttBroker)

def add_to_16(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt(data, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    bs = AES.block_size
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    cipher = AES.new(password, AES.MODE_ECB)
    data = cipher.encrypt(pad(data).encode('utf8'))
    encrypt_data = binascii.b2a_hex(data) # Output HEX
    # encrypt_data = base64.b64encode (data) #Climinate Comments, Output Base64 Format
    return encrypt_data.decode('utf8')

def decrypt(decrData, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    cipher = AES.new(password, AES.MODE_ECB)
    plain_text = cipher.decrypt(binascii.a2b_hex(decrData))
    return plain_text.decode('utf8')

if __name__ == "__main__":
    Password = input("Password: ")
    password = add_to_16(Password)
    while True:
        for _ in range(100):
            mess = add_to_16(str(randint(60, 100)))
            print('Pesan yang dikirim\t:', mess)
            encrypted = encrypt(str(mess), password)
            print ('Encrypted\t\t:', encrypted)
            print("Just published " + (encrypted) + " to topic AES")
            client.publish("AES", str(encrypted))

            sleep(3)