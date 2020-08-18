const user = [
  '老板',
  '管理员',
  '周润发',
  '周星星',
];

const categories = [
  'host',
  'monitor',
  'dpi',
  'image',
  'scap',
];

const testdata = {
  defaultEntry: {name: 'input name:'},
  columns: [{ title: '序号', dataIndex: 'key', key: 'key'}, { title: '名称', dataIndex: 'name', editable: true}],
  dataSource: [{ name: '/etc/', key: '1' }, { name: '/proc', key: '2' }, { name: '/usr/bin', key: '3' }],
};

const testCVEData = {
  defaultEntry: {name: 'input name:'},
  columns: [{ title: '序号', dataIndex: 'key', key: 'key'}, { title: 'CVE号', dataIndex: 'name', editable: true}],
  dataSource: [{ name: 'cve-2019-0001', key: '1' }, { name: 'cve-2019-0002', key: '2' }, { name: 'cve-2019-0003', key: '3' }],
};

const testScapData = {
  defaultEntry: {name: 'input name:'},
  columns: [{ title: '序号', dataIndex: 'key', key: 'key'}, { title: 'CIS序号', dataIndex: 'name', editable: true}],
  dataSource: [{ name: 'Section-1-1', key: '1' }, { name: 'Section-1-2', key: '2' },],
};

const testWhiteData = {
  defaultEntry: {src: 'input source ip', dst: 'input dst ip', sport: '*', dport: '80', protocol: 'http', key: 'n/a'},
  columns: [
    { title: '源', dataIndex: 'src', key: 'key', editable: true},
    { title: '目的', dataIndex: 'dst', editable: true},
    { title: '源端口', dataIndex: 'sport', editable: true},
    { title: '目的端口', dataIndex: 'dport', editable: true},
    { title: '协议', dataIndex: 'protocol', editable: true},
  ],
  dataSource: [{ key: '0', src: '*.*.*.*', dst: '10.10.1.1', sport: '*', dport: '80', protocol: 'http' }],
};

const testBlackData = {
  defaultEntry: {src: 'input source ip', dst: 'input dst ip', sport: '*', dport: '80', protocol: 'http', key: 'n/a'},
  columns: [
    { title: '源', dataIndex: 'src', key: 'key', editable: true},
    { title: '目的', dataIndex: 'dst',  editable: true},
    { title: '源端口', dataIndex: 'sport', editable: true},
    { title: '目的端口', dataIndex: 'dport', editable: true},
    { title: '协议', dataIndex: 'protocol', editable: true},
  ],
  dataSource: [{ key: '0', dst: '*.*.*.*', src: '10.10.1.1', sport: '*', dport: '8080', protocol: 'http' }],
};

function fakeList(count) {
  const list = [
    { key: 0, name: '拒绝服务攻击', title: '拒绝服务攻击', chosen: false, agents: [0, 1], customized: false, needConfig: false, config: null },
    { key: 1, name: 'Webshell检测', title: 'Webshell检测', chosen: true, agents: [1, 2], customized: false, needConfig: false, config: null },
    { key: 2, name: '本地提权', title: '本地提权', chosen: true, agents: [0], customized: false, needConfig: false, config: null },
    { key: 3, name: 'SQL嵌入攻击', title: 'SQL嵌入攻击', chosen: true, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 4, name: '自动化异常进程', title: '自动化异常进程', chosen: true, agents: [0], customized: false, needConfig: true, config: null },
    { key: 5, name: '关键文件夹监测', title: '关键文件夹监测', chosen: true, agents: [0], customized: false, needConfig: false, config: { file: { data: testdata } } },
    { key: 6, name: '可执行文件病毒扫描', title: '可执行文件病毒扫描', chosen: false, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 7, name: '数据隐私性保护', title: '数据隐私性保护', chosen: false, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 8, name: 'Fork炸弹', title: 'Fork炸弹', chosen: false, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 9, name: '路径遍历攻击', title: '路径遍历攻击', chosen: false, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 10, name: '本地缓冲区溢出', title: '本地缓冲区溢出', chosen: false, agents: [1, 2], customized: false, needConfig: false, config: null },
    { key: 11, name: '堆栈溢出', title: '堆栈溢出', chosen: false, agents: [0, 2], customized: false, needConfig: false, config: null },
    { key: 12, name: '堆栈发散攻击Spray', title: '堆栈发散攻击Spray', chosen: false, agents: [0, 1], customized: false, needConfig: false, config: null },
    { key: 13, name: '木马后门检测', title: '木马后门检测', chosen: true, agents: [0, 1, 2], customized: false, needConfig: false, config: null },
    { key: 14, name: '黑白名单网络隔离', title: '黑白名单网络隔离', chosen: false, agents: [1, 2], customized: false, needConfig: true, config: { white: { data: testWhiteData }, black: { data: testBlackData } }, },
    { key: 15, name: '应用层防火墙WAF', title: '应用层防火墙WAF', chosen: false, agents: [0, 1], customized: false, needConfig: true, config: null, } ,
    { key: 16, name: '自定义Log搜索检测', title: '自定义Log搜索检测', chosen: false, agents: [1], customized: false, needConfig: false, config: null },
    { key: 17, name: '黑白名单漏洞检测', title: '黑白名单漏洞检测', chosen: true, agents: [3], customized: false, needConfig: false, config: { white: { data: testCVEData}}},
    { key: 18, name: '无差别漏洞检测', title: '无差别漏洞检测', chosen: true, agents: [3], customized: false, needConfig: false, config: null },
    { key: 19, name: '可执行文件完整性', title: '可执行文件完整性', chosen: true, agents: [3], customized: false, needConfig: true, config: null },
    { key: 20, name: '数据隐私性保护', title: '数据隐私性保护', chosen: true, agents: [3], customized: false, needConfig: true, config: {} },
    { key: 21, name: '检测矿机', title: '检测矿机', chosen: false, agents: [3], customized: true, needConfig: false, config: null },
    { key: 22, name: '黑白名单合规检测', title: '黑白名单合规检测', chosen: true, agents: [4], customized: false, needConfig: true, config: { white: { data: testScapData } } },
    { key: 23, name: '无差别合规检测', title: '无差别合规检测', chosen: true, agents: [4], customized: false, needConfig: true, config: null },
  ];

  return list;
}


function getFakePolicies(req, res) {
  const params = req.query;

  let dataSource = fakeList(20);

  if (params.sorter) {
    const s = params.sorter.split('_');
    dataSource = dataSource.sort((prev, next) => {
      if (s[1] === 'descend') {
        return next[s[0]] - prev[s[0]];
      }

      return prev[s[0]] - next[s[0]];
    });
  }

  return res.json(dataSource);
}

export default {
  'GET  /api/v1/profiles/rules': getFakePolicies,
};
