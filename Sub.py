import paho.mqtt.client as mqtt
import time
from decouple import config

def on_message(client, userdata, message):
    print('received message: ', str(message.payload.decode("utf-8")))


mqttBroker = config('ADDRESS')

client = mqtt.Client("Subscriber")
client.connect(mqttBroker)

client.loop_start()

client.subscribe("RANDOM")
client.on_message=on_message

time.sleep(100)
client.loop_stop