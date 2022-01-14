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

# MQTT Initialization
mqttBroker = "192.168.10.108"
client = mqtt.Client('AES Publisher')
client.connect(mqttBroker)

class Cipher_AES:
	pad_default = lambda x, y: x + (y - len(x) % y) * " ".encode("utf-8")					# Method untuk menambahkan default padding
	pad_pkcs5 = lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")		# Method untuk menambahkan padding dengan metode pkcs5

	#Set IV dan key
	def __init__(self, key, iv):
		self.__key = key
		self.__iv = iv

	# Mode ECB
	def Cipher_MODE_ECB(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_ECB)

	# Mode CBC
	def Cipher_MODE_CBC(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_CBC,
										 self.__iv.encode("utf-8"))

	# Menjalankan proses enkripsi. Inputan berupa (Plain text, Metode enkripsi, Metode padding, Metode encoding)
	def encrypt(self, text, cipher_method, pad_method="", code_method=""):

		# Pemilihan mode ECB atau CBC
		if cipher_method.upper() == "MODE_ECB":
			self.Cipher_MODE_ECB()
		elif cipher_method.upper() == "MODE_CBC":
			self.Cipher_MODE_CBC()

		cipher_text = b"".join([self.__x.encrypt(i) for i in self.text_verify(text.encode("utf-8"), pad_method)])

		# Pemilihan metode encoding
		if code_method.lower() == "base64":
			return base64.encodebytes(cipher_text).decode("utf-8").rstrip()
		elif code_method.lower() == "hex":
			return binascii.b2a_hex(cipher_text).decode("utf-8").rstrip()
		else:
			return cipher_text.decode("utf-8").rstrip()

	# Verifikasi plaintext apakah sudah sesuai panjangnya atau belum
	def text_verify(self, text, method):
		while len(text) > 16:
			text_slice = text[:16]
			text = text[16:]
			yield text_slice
		else:
			if len(text) == 16:
				yield text
			else:
				yield self.pad_method(text, method)

	# Pemilihan metode padding yang akan digunakan
	def pad_method(self, text, method):
		print(text)
		if method == "":
			return Cipher_AES.pad_default(text, 16)
		elif method == "PKCS5Padding":
			return Cipher_AES.pad_pkcs5(text, 16)

def main(msg):
	#key = 'Mu8weQyDvq1HlAzN'
	key = 'Mu8weQyDvq1HlAzNMu8weQyDvq1HlAzN'
	#key = 'Mu8weQyDvq1HlAzN7fjY026Bjeu768db'
	iv = 'HIwu5283JGHsi76H'
	cipher_method = "MODE_CBC"
	pad_method = "PKCS5Padding"
	code_method = "base64"
	cipher_text = Cipher_AES(key, iv).encrypt(msg, cipher_method, pad_method, code_method)
	return cipher_text.replace('\n', '')

# Melakukan pencatatan ke dalam file .csv
def pencatatan(i, waktu):
     f = open('publish_AES.csv', 'a')
     f.write("Message ke-" + i + ";" + rand + ";" + msg + ";" + waktu + "\n")

message ={}
for i in range(10):
	rand = str(randint(60,100))
	msg = main(rand)
	now = str(datetime.now().timestamp())
	
	pencatatan(str(i), now)
	message['cipher'] = msg									# Memasukan value msg ke dalam key cipher
	message['datetime'] = now								# Memasukan waktu ke dalam key datetime
	stringify = json.dumps(message, indent=2)				# Mengubah format JSON menjadi string
	client.publish("AES", stringify)						# Publish JSON stringify ke MQTT broker

	print("Plaintext\t: ", rand)
	print("Encrypted\t: ", msg)
	print("Just published a message to topic AES at "+ now)