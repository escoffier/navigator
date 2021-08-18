package re

import "regexp"

var SimpleRegex Regexes

var regexExpr = []string{
	`[\r\n;\/\*]+\s*\b(include|require)(_once)?\b[\s\(]*['"][^\n'"]{1,100}((\.(jpg|png|txt|jpeg|log|tmp|db|cache)|\_(tmp|log))|((http|https|file|php|data|ftp)\:\/\/\[.{0,25}))['"][\s\)]*[\r\n;\/\*]+`,
	`\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))`,
	`(array_map|call_user_func|call_user_func_array|new\s*ReflectionFunction|register_shutdown_function|register_tick_function|new\s*ArrayObject[\s\S]*->u[ak]sort)\s*\(+\s*(['"]\s*(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|[^'"]*\\x).{0,200}|(\$_(GET|POST|REQUEST|COOKIE)\[[^,;\)]{0,250},[^;\),]{0,50}\$[^;\),]{0,50}\)))`,
	`((array_filter|array_reduce|array_diff_ukey|array_udiff|array_walk|uasort|uksort|usort|new\s*SQLite3[\s\S]*->\s*createFunction)\s*\(+\s*.{1,100}|PDO::FETCH_FUNC\s*),\s*(['"]\s*(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*['"]|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]+.{1,25}|(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))\s*\)`,
	`sqlite_create_function\s*\([\s\S]{0,200}(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[\s\S]{0,200}sqlite_create_function\s*\(`,
	`\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))`,
	`\b(mb_ereg_replace|mb_eregi_replace)\b\s*\((.*,){3}\s*(['"][^,"'\)]*e[^,"'\)]*['"]|.*(\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25}).*|chr\s*\(\s*101|chr\s*\(\s*0x65|chr\s*\(\s*0145)\s*\)`,
	`array_walk(_recursive)?\s*\([^;,]*,\s*(['"]\s*(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|preg_replace)\s*['"]|(\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25}))`,
	`\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?['"]php:\/\/input`,
	`^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php`,
	`ob_start\s*\(+\s*(['"]\s*(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec).{0,20}|['"]\s*\w+[\s\S]{1,50}phpinfo\s*\(\s*\))`,
	`\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b\s*\(((\$_SERVER|\$_ENV|getenv|\$GLOBALS)\s*[\[\(]\s*['"]+(REQUEST_URI|QUERY_STRING|HTTP_[\w_]+|REMOTE_[\w_])['"\s]+\s*[\]\)]|php:\/\/input|exif_read_data\s*\()`,
	`eval\("\?>"\.|gzinflate\(base64_decode\(|eval\(base64_decode\(|cat\s*\/etc\/passwd|Safe_Mode\s*Bypass`,
	`preg_replace\s*\(\s*['"][^;]*e[^;]*['"],([^;]{0,30}\\x|[^;\)]{200,300})|\$back_connect="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU2|define\('gzip',function_exists\("ob_gzhandler"\)|chr\(112\)\.chr\(97\)\.chr\(115\)\.chr\(115\)|687474703a2f2f377368656c`,
	`ini_get\s*\(\s*"disable_functions"\s*\)|gzuncompress\(base64_decode\(|crypt\(\$_SERVER\['HTTP_H0ST'\],\d+\)==|if\(file_exists\(\$settings\['STOPFILE'\]\)\)`,
	`\$nofuncs='no\s*exec\s*functions|udf\.dll|\$b374k|POWER-BY\s*WWW.XXDDOS.COM|<title>Safes\s*Mode\s*Shell<\/title>|Siyanur\.PHP\s*<\/font>|c999shexit\(\)|\$c99sh_|c99_sess_put\(|Coded\s*by\s*cyb3r|cyb3r_getupdate\(|coded\s*by\s*tjomi4|john\.barker446@gmail\.com|eval\("\\\$x=gzin"|eval\("\?>"\.gzinflate\(base64_decode\(|eval\(gzinflate\(base64_decode\(|eval\(gzuncompress\(base64_decode\(|eval\(gzinflate\(str_rot13\(base64_decode\(|function_exists\("zigetwar_buff_prepare"\)|dQ99shell|r57shell|c99shell|lama's'hell\s*v|Carbylamine\s*PHP\s*Encoder|Safe\s*Mode\s*Shell|\$dI3h=\${'_REQUEST'};|new\s*COM\("IIS:\/\/localhost\/w3svc"\)|n57http-based\[\s*-\]terminal|Dosya\s*Olu|errorlog\("BACKEND:\s*startReDuh,|form\s*name=sh311Form|PHPJackal<br>|Reddragonfly's\s*WebShell|\("system"==\$seletefunc\)\?system\(\$shellcmd\)|eNrsvGmT40iSKPZ5xmz|CrystalShell\s*v\.|Special\s*99\s*Shell|Simple\s*PHP\s*Mysql\s*client|'_de'\.'code'|phpsocks5_encrypt\(|define\('PHPSHELL_VERSION',|ZXZhbCgkX1BPU1RbMV0p|\$__H_H\(\$__C_C`,
	`PD9waHANCiRzX3ZlciA9ICIxLjAiOw0KJHNfdGl0bGUgPSAiWG5vbnltb3V4IFNoZWxsIC|GFnyF4lgiGXW2N7BNyL5EEyQA42LdZtao2S9f|IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vYmFzaCAtaSI7|setcookie\("N3tsh_surl"\);|function\s*Tihuan_Auto|\$_COOKIE\['b374k'\]|function_exists\("k1r4_sess_put"\)|http:\/\/www.7jyewu.cn\/|scookie\('phpspypass|PHVayv.php\?duzkaydet=|phpRemoteView<\/a>|define\('envlpass',|KingDefacer_getupdate\(|relative2absolute\(|Host:\s*old.zone-h.org|<h3>PHPKonsole<\/h3>|\$_SESSION\['hassubdirs'\]\[\$treeroot\]|strtolower\(\$cmd\)\s*==\s*"canirun"|\$shell\s*=\s*'uname\s*-a;\s*w;\s*id;|Avrasya\s*Veri\s*ve\s*NetWork|<h1>Linux Shells<\/h1>|\$MyShellVersion\s*=\s*"MyShell|<a\s*href="http:\/\/ihacklog.com\/"|setcookie\(\s*"mysql_web_admin_username"\s*\)|<title>PHP\s*Shell\s*[^\n\r]*<\/title>|\$OOO000000=urldecode|1MSSYowqjzlVVAwAoHHFXzQ5Lc|'xiaoqiwangluo'|EqQC1FhyXxpEi7l2g\+yNjW62S|\$_uU\(83\)\.\$_uU\(84\)|7kyJ7kSKioDTWVWeRB3TiciL1UjcmRiLn4SKiAETs90cuZlTz5mROtHWHdWfRt0ZupmVRNTU2Y2MVZkT8|<title>\s*ARS\s*Terminator\s*Shell<\/title>|base64_decode\("R0lGODdhEgASAKEAAO7u7gAAAJmZmQAAACwAAA|\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00|'<title>W3D\s*Shell|\$back_connect="IyEvdXNyL2Jpbi9wZXJsD`,
	`\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\[(['"]\w+['"]|\d+)\]\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\[(['"]\w+['"]|\d+)\]\s*\)`,
	`(unserialize|assert|passthru|(shell|pcntl|)exec|(\s|=)system|(expect_|)popen|proc_open|eval|dl|register_tick_function|register_shutdown_function)(?:(?:["'` + "`" + `$(\s]|(\/\*(?:[\S\s][^\*\/]*)\*\/)|\/\*\*\/|((\/\/|#))(?:[\S\s][^"'` + "`" + `]*))+)(?:.*)\$_(?:GET|POST|COOKIE|REQUEST|ENV|SERVER|FILES|SESSION)`,
	`(phpinfo|highlight_file|show_source)(?:(?:["'` + "`" + `$(\s]|(\/\*(?:[\S\s][^\*\/]*)\*\/)|\/\*\*\/|((\/\/|#))(?:[\S\s][^"'` + "`" + `]*))+)`,
}

func init() {
	SimpleRegex = make([]*regexp.Regexp, 0, len(SimpleRegex))
	for i := range regexExpr {
		r := regexp.MustCompile(regexExpr[i])
		SimpleRegex = append(SimpleRegex, r)
	}
}
