package cnvd

import "encoding/xml"

type cnvdCVE struct {
	XMLName   xml.Name `xml:"cve"`
	CVENumber string   `xml:"cveNumber"` // CVE-2019-13467
	CVEURL    string   `xml:"cveUrl"`    // https://nvd.nist.gov/vuln/detail/CVE-2019-13467
}

type cnvdCVEs struct {
	XMLName xml.Name  `xml:"cves"`
	CVEs    []cnvdCVE `xml:"cve"`
}

type cnvdVulnerability struct {
	XMLName     xml.Name `xml:"vulnerability"`
	Number      string   `xml:"number"` // CNVD-2020-60468
	CVEs        cnvdCVEs `xml:"cves"`
	Title       string   `xml:"title"`         // Western Digital SSD Dashboard和SanDisk SSD Dashboard输入验证错误漏洞
	Severity    string   `xml:"serverity"`     // 中 (typo intended)
	RefLink     string   `xml:"referenceLink"` // https://nvd.nist.gov/vuln/detail/CVE-2019-13467
	Description string   `xml:"description"`   // Western Digital SSD Dashboard和SanDisk SSD Dashboard都是美国西部数据（Western....
}

type cnvdReport struct {
	XMLName         xml.Name            `xml:"vulnerabilitys"`
	Vulnerabilities []cnvdVulnerability `xml:"vulnerability"`
}

// <vulnerabilitys>
//     <vulnerability>
//         <number>CNVD-2020-60468</number>
//         <cves>
//             <cve>
//                 <cveNumber>CVE-2019-13467</cveNumber>
//                 <cveUrl>https://nvd.nist.gov/vuln/detail/CVE-2019-13467</cveUrl>
//             </cve>
//         </cves>
//         <title>Western Digital SSD Dashboard和SanDisk SSD Dashboard输入验证错误漏洞</title>
//         <serverity>中</serverity>
//         <products>
//             <product>Western Digital Western Digital SSD Dashboard &lt;2.5.1.0</product>
//             <product>Western Digital SanDisk SSD Dashboard &lt;2.5.1.0</product>
//         </products>
//         <isEvent>通用软硬件漏洞</isEvent>
//         <submitTime>2019-11-08</submitTime>
//         <openTime>2020-11-04</openTime>
//         <referenceLink>https://nvd.nist.gov/vuln/detail/CVE-2019-13467</referenceLink>
//         <formalWay>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：&#xD;
// https://www.westerndigital.com/support/productsecurity/wdc-19009-sandisk-and-western-digital-ssd-dashboard-vulnerabilities</formalWay>
//         <description>Western Digital SSD Dashboard和SanDisk SSD Dashboard都是美国西部数据（Western Digital）公司的产品。Western Digital SSD Dashboard是一款用于管理和监控SSD（固态驱动器）设备的仪表板软件。SanDisk SSD Dashboard是一款用于管理和监控SanDisk SSD（固态驱动器）设备的仪表板软件。
// Western Digital SSD Dashboard 2.5.1.0之前版本和SanDisk SSD Dashboard 2.5.1.0之前版本中存在输入验证错误漏洞。该漏洞源于网络系统或产品未对输入的数据进行正确的验证。目前没有详细漏洞细节提供。</description>
//         <patchName>Western Digital SSD Dashboard和SanDisk SSD Dashboard输入验证错误漏洞的补丁</patchName>
//         <patchDescription>Western Digital SSD Dashboard和SanDisk SSD Dashboard都是美国西部数据（Western Digital）公司的产品。Western Digital SSD Dashboard是一款用于管理和监控SSD（固态驱动器）设备的仪表板软件。SanDisk SSD Dashboard是一款用于管理和监控SanDisk SSD（固态驱动器）设备的仪表板软件。&#xD;
// &#xD;
// Western Digital SSD Dashboard 2.5.1.0之前版本和SanDisk SSD Dashboard 2.5.1.0之前版本中存在输入验证错误漏洞。该漏洞源于网络系统或产品未对输入的数据进行正确的验证。目前没有详细漏洞细节提供。目前，供应商发布了安全公告及相关补丁信息，修复了此漏洞。</patchDescription>
//     </vulnerability>
// ...
