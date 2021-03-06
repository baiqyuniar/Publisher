import Cryptodome.Cipher.AES
import Cryptodome.Random
import base64
import binascii
from random import randint
from time import sleep, time
import paho.mqtt.client as mqtt
import timeit
from datetime import datetime
import json

# MQTT
mqttBroker = "34.101.187.83"
client = mqtt.Client('AES Publisher')
client.connect(mqttBroker)

class Cipher_AES:
	pad_default = lambda x, y: x + (y - len(x) % y) * " ".encode("utf-8")
	unpad_default = lambda x: x.rstrip()
	pad_user_defined = lambda x, y, z: x + (y - len(x) % y) * z.encode("utf-8")
	unpad_user_defined = lambda x, z: x.rstrip(z)
	pad_pkcs5 = lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")
	unpad_pkcs5 = lambda x: x[:-ord(x[-1])]

	def __init__(self, key, iv):
		self.__key = key
		self.__iv = iv

	def set_key(self, key):
		self.__key = key

	def get_key(self):
		return self.__key

	def set_iv(self, iv):
		self.__iv = iv

	def get_iv(self):
		return self.__iv

	def Cipher_MODE_ECB(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_ECB)

	def Cipher_MODE_CBC(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_CBC,
										 self.__iv.encode("utf-8"))

	def encrypt(self, text, cipher_method, pad_method="", code_method=""):
		if cipher_method.upper() == "MODE_ECB":
			self.Cipher_MODE_ECB()
		elif cipher_method.upper() == "MODE_CBC":
			self.Cipher_MODE_CBC()
		cipher_text = b"".join([self.__x.encrypt(i) for i in self.text_verify(text.encode("utf-8"), pad_method)])
		if code_method.lower() == "base64":
			return base64.encodebytes(cipher_text).decode("utf-8").rstrip()
		elif code_method.lower() == "hex":
			return binascii.b2a_hex(cipher_text).decode("utf-8").rstrip()
		else:
			return cipher_text.decode("utf-8").rstrip()

	#text verify for AES-192
	def text_verify(self, text, method):
		while len(text) >16:
			text_slice = text[:16]
			text = text[16:]
			yield text_slice
		else:
			if len(text) == 16:
				yield text
			else:
				yield self.pad_method(text, method)


	#Pad method AES-192
	def pad_method(self, text, method):
		if method == "":
			return Cipher_AES.pad_default(text, 16)
		elif method == "PKCS5Padding":
			return Cipher_AES.pad_pkcs5(text, 16)
		else:
			return Cipher_AES.pad_user_defined(text, 16,  method)

def publish(topic, message):
	client.publish(topic, message)


def prints(plaintext, encrypted_message, date_now):
	print("Plaintext\t: ", plaintext)
	print("Encrypted\t: ", encrypted_message)
	print("Length\t\t: ", len(encrypted_message), "Bytes")
	print("Just published a message to topic AES at "+ date_now)
	print("\n")


def main(plaintext):
#	key = 'Mu8weQyDvq1HlAzN'
	key = 'Mu8weQyDvq1HlAzN7fjY026B'
#	key = 'Mu8weQyDvq1HlAzN7fjY026Bjeu768db'
	iv = 'HIwu5283JGHsi76H'
	text = plaintext
	cipher_method = "MODE_ECB"
	pad_method = "PKCS5Padding"
	code_method = "hex"
	cipher_text = Cipher_AES(key, iv).encrypt(text, cipher_method, pad_method, code_method)
	return cipher_text.replace('\n', '')

def pencatatan(i, date_now, plaintext, encrypted_message):
     f = open('Publish_AES.csv', 'a')
     f.write("Message ke-" + i + ";" + plaintext + ";" + encrypted_message + ";" + date_now + "\n")

# Record the start time
start = timeit.default_timer()
message ={}

for i in range(10000):
	# Creating random integer as plaintext
	plaintext = str(randint(60,100))

	# Encrypting the plaintext
	encrypted_message = main(plaintext)
	date_now = str(datetime.now().timestamp())

	# Make the data record
	pencatatan(str(i), date_now, plaintext, encrypted_message)

	# Make the JSON data
	message['cipher'] = encrypted_message
	message['datetime'] = date_now
	stringify = json.dumps(message, indent=2)

	# Publishing the data
	publish('AES', stringify)

	# Displaying the data
	prints(plaintext, encrypted_message, date_now)

# Record the finished time
stop = timeit.default_timer()
encryption_duration = stop - start
print("Waktu akumulasi : "+str(encryption_duration))
