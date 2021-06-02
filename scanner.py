import sys, getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import TCP, IP, ICMP, sr1, RandShort, sr

def main(argv):

	scanType = ""
	givenPorts = "80"
	destinationIP = ""

	try:
		opts, args = getopt.getopt(argv,"",["p=","scanRange=","ICMP","SYN"])
	except getopt.GetoptError as err:
		print(str(err))
		sys.exit(2)
	for opt, arg in opts:
		if opt in ('--p', '--ports'):
			givenPorts = arg
		elif opt == '--ICMP':
			scanType = "ICMP"
		elif opt == '--SYN':
			scanType = "SYN"
	try:
		destinationIP = args[-1]
	except Exception:
		print("No ip specified")
		sys.exit(2)
		

	allPorts = parser(givenPorts)
	for i in allPorts: #checking port validity
		if int(i) == 0 or int(i) > 4294967295:
			print("Invalid port number:", i)
			sys.exit(2)

	if scanType == "SYN":
		doTcp(allPorts, destinationIP)
	elif scanType == "ICMP":
		doIcmp(destinationIP)
	else:
		print("Error: no protocol specified.")
	sys.exit(0)



def doTcp(allPorts, destinationIp):
	dst_ip = destinationIp
	src_port = RandShort()
	for i in allPorts:
		try:
			dst_port=int(i)
		except ValueError:
			print("At least one of the ports entered is not a number.")
			break

		tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
		if(str(type(tcp_connect_scan_resp))=="<class 'NoneType'>"):
			print(dst_port, "is closed")
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
				print(dst_port, "is open")
			elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				print(dst_port, "is closed")


def doIcmp(dst_ip):
	ans=sr1(IP(dst=dst_ip)/ICMP(), timeout=10)
	if ans:
		print(dst_ip, "exists")
	else:
		print(dst_ip, "does not exist")


def parser(input):
	ports = input.split(",") #split around commas
	toScan = []
	for i in ports:
		if i.__contains__("-"):
			ranges = i.split("-") #split around - for ranges
			start = ranges[0]
			end = ranges[1]

			if(len(ranges) > 2): #invalid input
				print("Invalid range:", ranges)
				sys.exit(2)
			try:
				if end > start: #starting range is larger than ending range
					print("Invalid port range:", start,"-",end)
					sys.exit(2)
				for j in range(int(start), int(end)): #add all ports in range
					toScan.append(int(j))
				toScan.append(int(end))
			except Exception:
				print("Ports must be numbers.")
				sys.exit(2)
		else:
			toScan.append(i) #if it is not a range, just add the port given.
	return toScan

if __name__ == "__main__":
	main(sys.argv[1:])