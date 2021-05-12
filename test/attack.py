import sys, argparse, os, time

attck_dict = {'ca':'credential access', 'def':'defense evasion', 'disc':'discovery', 'exec':'execution', 'exf':'exfiltration', 'move':'lateral movement', 'pers':'persistence', 'priv':'privilege escalation', 'all':'all scripts'}

goat_dict = {'chroot':'CHROOT-CONTAINER-ESCAPE', 'dind':'docker-in-docker', 'info':'Gaining-environment-information', 'bypassns':'K8s-Namespaces-bypass'}

script_dir = '/test/'


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attck", help="run ATT&CK-Script")
    parser.add_argument("--goat", help="run K8S-Goat-Script")
    parser.add_argument("--cve", help="run CVE-POC", action="store_true")
    parser.add_argument("--rs", help="run Reverse-Shell-Script", action="store_true")
    parser.add_argument("--cm", help="run Crypto-Miner-Script", action="store_true")
    parser.add_argument("--dp", help="run Drift-Prevention-Script", action="store_true")
    parser.add_argument("--report", help="show attack's results", action="store_true")
    return parser.parse_args()

def run_cmd(type, command):
	os.system(script_dir+type+'/'+command+'.sh')
	show_results("\033[31m"+"Successfully exploit "+type+' '+eval(type+'_dict')[command]+" attacks\033[0m")

def show_results(success_words):
	global attack_list
	print(success_words)
	with open('/test/results.txt', 'a+') as f:
		f.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+': '+success_words+'\n')

args = parse_args()

if args.attck:
	if args.attck == 'all':
		os.system('/test/attck/script.sh')
		print("\033[31m"+"Successfully exploit all attck attacks\033[0m")
	else:
		run_cmd('attck', args.attck)

if args.goat:
	run_cmd('goat', args.goat)


if args.cve:
	os.system('/test/cve/CVE-2019-14287/script.sh')
	os.system('python3 /test/cve/CVE-2019-3874/server.py')
	os.system('python3 /test/cve/CVE-2020-14386/server.py')
	os.system('/usr/lib/go-1.10/bin/go run /test/cve/CVE-2019-5736/main.go')
	show_results("\033[31m"+"Successfully exploit all cve attacks\033[0m")


if args.rs:
	os.system('/test/rerverse_shell/RS-NC/script.sh')
	os.system('/test/rerverse_shell/RS-SOCKET_AND_DUP2/script.sh')
	show_results("\033[31m"+"Successfully exploit all reverse shelll attacks\033[0m")

if args.cm:
	os.system('/test/crypto_miner/script.sh')
	show_results("\033[31m"+"Successfully exploit crypto miner attacks\033[0m")

if args.dp:
	os.system('/test/drift-prevention/script.sh')
	show_results("\033[31m"+"Successfully exploit drift prevention attacks\033[0m")

if args.report:
	with open('/test/results.txt', 'r') as f:
		for result in f:
			print(result)