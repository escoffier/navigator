package scannermodel

var riskDetail map[string]string
var recommend map[string]string

func WebshellRiskEN(det string) string {
	if riskDetail == nil {
		riskDetail =
			map[string]string{
				"asp webshell":         "asp webshell",
				"PHP后门":                "PHP backdoor",
				"ASP后门":                "ASP backdoor",
				"php webshell":         "php webshell",
				"ASP一句话后门":             "ASP backdoor",
				"JFoler9 jsp webshell": "JFoler9 jsp webshell",
				"DDOS类PHP攻击后门":         "DDOS attack backdoor",
				"JSP小马":                "JSP Trojan",
				"JSPSPY JSP大马":         "JSP Trojan",
				"PHP上传后门":              "PHP backdoor",
				"图片型PHP后门":             "PHP backdoor",
				"JSP Caidao":           "JSP Caidao",
				"JFolder jsp webshell": "JFolder jsp webshell",
				"ASP小马":                "JSP Trojan",
				"变形PHP一句话后门":           "PHP backdoor",
				"危险的PHP反序列化操作":         "PHP deserialization operation",
				"JSP后门":                "JSP backdoor",
				"JSP可疑文件":              "JSP Suspicious file",
				"weevely PHP后门":        "weevely PHP backdoor",
				"jsp webshell":         "jsp webshell",
				"C99SHELL PHP大马":       "C99SHELL PHP Trojan",
				"ASP加密脚本":              "ASP encryption script",
				"PHP变量函数后门代码":          "PHP variable function backdoor code",
				"jshell JSP大马":         "jshell JSP Trojan",
				"ASP大马":                "JSP Trojan",
				"aspx webshell":        "aspx webshell",
				"PHP大马":                "PHP Trojan",
				"命令执行ASP后门":            "Command Execution ASP Backdoor",
				"可疑的PHP一句话":            "Suspicious PHP word",
				"pwn jsp webshell":     "pwn jsp webshell",
				"植入类PHP后门":             "Implanting a PHP-like backdoor",
				"jspx webshell":        "jspx webshell",
				"ghost PHP大马":          "ghost PHP Trojan",
				"PHP一句话后门":             "PHP backdoor",
				"odd PHP后门":            "odd PHP backdoor",
				"K81 JSP后门":            "K81 JSP backdoor",
				"cmd PHP小马":            "cmd PHP Trojan",
				"dodoziph PHP后门":       "dodoziph PHP backdoor",
				"cnseay PHP一句话后门":      "cnseay PHP backdoor",
				"PHP IIS SPY":          "PHP IIS SPY",
				"webshell":             "webshell",
				"PHP异常包含":              "PHP exception contains",
				"变形ASP一句话后门":           "JSP backdoor",
				"PHP小马":                "PHP Trojan",
				"Ani PHP小马":            "PHP Trojan",
				"EFSO ASP后门":           "JSP backdoor",
				"K8 JSP小马":             "JSP Trojan",
				"寄生虫SEO类PHP后门":         "PHP backdoor",
				"catches PHP后门":        "PHP backdoor",
				"ntdaddy ASP后门":        "ASP backdoor",
				"404 ASP后门":            "ASP backdoor",
				"海洋顶端ASP大马":            "JSP Trojan",
				"菜刀ASP一句话后门":           "JSP backdoor",
				"菜刀PHP一句话后门":           "JSP backdoor",
				"疑似PHP后门":              "PHP backdoor",
				"疑似ASP后门":              "PHP backdoor",
				"PHP加密文件":              "PHP encrypted file",
				"pl webshell":          "pl webshell",
				"冰蝎3.0 PHP":            "PHP Trojan",
				"Godzilla JSP":         "Godzilla JSP",
				"Godzilla ASPX":        "Godzilla ASPX",
				"冰蝎3.0 ASPX":           "jspx webshell",
				"冰蝎3.0 JSP":            "JSP Trojan",
				"Godzilla PHP":         "Godzilla PHP",
				"冰蝎3.0 asp":            "JSP Trojan",
			}
	}
	des := riskDetail[det]
	if des == "" {
		return "webshell"
	}

	return des
}

func WebshellRecommendEN(rec string) string {
	if recommend == nil {
		recommend = map[string]string{
			"建议清理":            "recommend clean",
			"建议人工确认":          "recommend manual verification",
			"建议进行人工确认":        "recommend manual verification",
			"具有执行命令的操作，请检查文件": "has an action to execute the command, check the file",
			"检查确认后删除相关代码":     "Delete the relevant code after checking and confirming",
			"$$利用方式2":         "recommend clean",
			"建议删除":            "recommend clean",
			"JSP后门，建议清理":      "recommend clean",
			"ASPX后门，建议清理":     "recommend clean",
			"PHP后门，建议清理":      "recommend clean",
			"asp后门，建议清理":      "recommend clean",
			"建议人工鉴定":          "recommend clean",
		}
	}
	ans := recommend[rec]
	if ans == "" {
		ans = "recommend clean"
	}
	return ans
}
