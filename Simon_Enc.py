from __future__ import print_function
from random import randint
from time import sleep
from collections import deque
import paho.mqtt.client as mqtt
import timeit
from datetime import datetime
import json

#MQTT
mqttBroker = "34.101.187.83"
client = mqtt.Client("Simon Publisher")
client.connect(mqttBroker)

class SimonCipher(object):
    """Simon Block Cipher Object"""

    # Z Arrays (stored bit reversed for easier usage)
    z0 = 0b01100111000011010100100010111110110011100001101010010001011111
    z1 = 0b01011010000110010011111011100010101101000011001001111101110001
    z2 = 0b11001101101001111110001000010100011001001011000000111011110101
    z3 = 0b11110000101100111001010001001000000111101001100011010111011011
    z4 = 0b11110111001001010011000011101000000100011011010110011110001011

    # valid cipher configurations stored:
    # block_size:{key_size:(number_rounds,z sequence)}
    __valid_setups = {32: {64: (32, z0)},
                      48: {72: (36, z0), 96: (36, z1)},
                      64: {96: (42, z2), 128: (44, z3)},
                      96: {96: (52, z2), 144: (54, z3)},
                      128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}

    __valid_modes = ['ECB', 'CBC']

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):
        """
        Initialize an instance of the Simon block cipher.
        :param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :param mode: String representing which cipher block mode the object should initialize with
        :param init: IV for CTR, CBC, PCBC, CFB, and OFB modes
        :param counter: Initial Counter value for CTR mode
        :return: None
        """

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds, Z Sequence, and Key Size
        try:
            self.rounds, self.zseq = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** self.block_size) - 1)
            self.iv_upper = self.iv >> self.word_size
            self.iv_lower = self.iv & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** self.block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        m = self.key_size // self.word_size
        self.key_schedule = []

        # Create list of subwords from encryption key
        k_init = [((self.key >> (self.word_size * ((m - 1) - x))) & self.mod_mask) for x in range(m)]

        k_reg = deque(k_init)  # Use queue to manage key subwords

        round_constant = self.mod_mask ^ 3  # Round Constant is 0xFFFF..FC

        # Generate all round keys
        for x in range(self.rounds):

            rs_3 = ((k_reg[0] << (self.word_size - 3)) + (k_reg[0] >> 3)) & self.mod_mask

            if m == 4:
                rs_3 = rs_3 ^ k_reg[2]

            rs_1 = ((rs_3 << (self.word_size - 1)) + (rs_3 >> 1)) & self.mod_mask

            c_z = ((self.zseq >> (x % 62)) & 1) ^ round_constant

            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]

            self.key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)

    def encrypt_round(self, x, y, k):
        """
        Complete One Feistel Round
        :param x: Upper bits of current plaintext
        :param y: Lower bits of current plaintext
        :param k: Round Key
        :return: Upper and Lower ciphertext segments
        """

        # Generate all circular shifts
        ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
        ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
        ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

        # XOR Chain
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        new_x = k ^ xor_2

        return new_x, x

    def encrypt(self, plaintext):
        """
        Process new plaintext into ciphertext based on current cipher object setup
        :param plaintext: Int representing value to encrypt
        :return: Int representing encrypted value
        """
        try:
            b = (plaintext >> self.word_size) & self.mod_mask
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext as int')
            raise

        if self.mode == 'ECB':
            b, a = self.encrypt_function(b, a)

        elif self.mode == 'CBC':
            b ^= self.iv_upper
            a ^= self.iv_lower
            b, a = self.encrypt_function(b, a)

            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a

        ciphertext = (b << self.word_size) + a

        return ciphertext

    def encrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Simon Fiestel function to encrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper bytes of plaintext input
                    limited by word size of currently configured cipher
        lower_word: int of lower bytes of plaintext input
                    limited by word size of currently configured cipher
        x,y:        int of Upper and Lower ciphertext words
        """
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
            # Generate all circular shifts
            ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2

        return x, y

    def update_iv(self, new_iv):
        if new_iv:
            try:
                self.iv = new_iv & ((2 ** self.block_size) - 1)
                self.iv_upper = self.iv >> self.word_size
                self.iv_lower = self.iv & self.mod_mask
            except TypeError:
                print('Invalid Initialization Vector!')
                print('Please provide IV as int')
                raise
        return self.iv

def pencatatan(i, waktu):
    f = open('publish_Simon.csv', 'a')
    f.write("Message ke-" + i + ";" + str(mess) + ";" + str(simon) + ";" + waktu + "\n")

# Mencatat waktu mulai
start = timeit.default_timer()
#key = 0x1f1e1d1c1b1a19181716151413121110
#key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908
key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
#cipher = SimonCipher(key, 256, 128, 'ECB')
cipher = SimonCipher(key, 256, 128, 'CBC', 0x123456789ABCDEF0)
message ={}
for i in range(10000):
    mess = randint (60,100)
    print("Plaintext\t: ", mess)
    simon = cipher.encrypt(mess)
    now = str(datetime.now().timestamp())
    pencatatan(str(i), now)
    message['cipher'] = hex(simon)
    message['datetime'] = now
    stringify = json.dumps(message, indent=2)
    client.publish("SIMON", stringify)
    print("Encrypted\t: ",hex(simon))
    print("Just published a message to topic SIMON at "+ now)


# Mencatat waktu selesai
stop = timeit.default_timer()
lama_enkripsi = stop - start
print("Waktu akumulasi : "+str(lama_enkripsi))
