const titles = [
  'Alipay',
  'Angular',
  'Ant Design',
  'Ant Design Pro',
  'Bootstrap',
  'React',
  'Vue',
  'Webpack',
];
const avatars = [
  'https://gw.alipayobjects.com/zos/rmsportal/WdGqmHpayyMjiEhcKoVE.png', // Alipay
  'https://gw.alipayobjects.com/zos/rmsportal/zOsKZmFRdUtvpqCImOVY.png', // Angular
  'https://gw.alipayobjects.com/zos/rmsportal/dURIMkkrRFpPgTuzkwnB.png', // Ant Design
  'https://gw.alipayobjects.com/zos/rmsportal/sfjbOqnsXXJgNCjCzDBL.png', // Ant Design Pro
  'https://gw.alipayobjects.com/zos/rmsportal/siCrBXXhmvTQGWPNLBow.png', // Bootstrap
  'https://gw.alipayobjects.com/zos/rmsportal/kZzEzemZyKLKFsojXItE.png', // React
  'https://gw.alipayobjects.com/zos/rmsportal/ComBAopevLwENQdKWiIn.png', // Vue
  'https://gw.alipayobjects.com/zos/rmsportal/nxkuOJlFJuAUhzlMTCEe.png', // Webpack
];
const covers = [
  'https://gw.alipayobjects.com/zos/rmsportal/uMfMFlvUuceEyPpotzlq.png',
  'https://gw.alipayobjects.com/zos/rmsportal/iZBVOIhGJiAnhplqjvZW.png',
  'https://gw.alipayobjects.com/zos/rmsportal/iXjVmWVHbCJAyqvDxdtx.png',
  'https://gw.alipayobjects.com/zos/rmsportal/gLaIAoVWTtLbBWZNYEMg.png',
];
const desc = [
  '那是一种内在的东西， 他们到达不了，也无法触及的',
  '希望是一个好东西，也许是最好的，好东西是不会消亡的',
  '生命就像一盒巧克力，结果往往出人意料',
  '城镇中有那么多的酒馆，她却偏偏走进了我的酒馆',
  '那时候我只会想自己想要什么，从不想自己拥有什么',
];
const user = [
  '付小小',
  '曲丽丽',
  '林东东',
  '周星星',
  '吴加好',
  '朱偏右',
  '鱼酱',
  '乐哥',
  '谭小仪',
  '仲尼',
];

function fakeList(count) {
  const list = [];

  for (let i = 0; i < count; i += 1) {
    list.push({
      id: `fake-list-${i}`,
      owner: user[i % 10],
      title: titles[i % 8],
      avatar: avatars[i % 8],
      cover: parseInt(`${i / 4}`, 10) % 2 === 0 ? covers[i % 4] : covers[3 - (i % 4)],
      status: ['active', 'exception', 'normal'][i % 3],
      percent: Math.ceil(Math.random() * 50) + 50,
      logo: avatars[i % 8],
      href: 'https://ant.design',
      updatedAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i).getTime(),
      createdAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i).getTime(),
      subDescription: desc[i % 5],
      description:
        '在中台产品的研发过程中，会出现不同的设计规范和实现方式，但其中往往存在很多类似的页面和组件，这些类似的组件会被抽离成一套标准规范。',
      activeUser: Math.ceil(Math.random() * 100000) + 100000,
      newUser: Math.ceil(Math.random() * 1000) + 1000,
      star: Math.ceil(Math.random() * 100) + 100,
      like: Math.ceil(Math.random() * 100) + 100,
      message: Math.ceil(Math.random() * 10) + 10,
      content:
        '段落示意：蚂蚁金服设计平台 ant.design，用最小的工作量，无缝接入蚂蚁金服生态，提供跨越设计与开发的体验解决方案。蚂蚁金服设计平台 ant.design，用最小的工作量，无缝接入蚂蚁金服生态，提供跨越设计与开发的体验解决方案。',
      members: [
        {
          avatar: 'https://gw.alipayobjects.com/zos/rmsportal/ZiESqWwCXBRQoaPONSJe.png',
          name: '曲丽丽',
          id: 'member1',
        },
        {
          avatar: 'https://gw.alipayobjects.com/zos/rmsportal/tBOxZPlITHqwlGjsJWaF.png',
          name: '王昭君',
          id: 'member2',
        },
        {
          avatar: 'https://gw.alipayobjects.com/zos/rmsportal/sBxjgqiuHMGRkIjqlQCd.png',
          name: '董娜娜',
          id: 'member3',
        },
      ],
    });
  }

  return list;
}

const sourceData = [];
const vulnData = [
  { name: 'CVE-2019-001', key: 'cve_0', hasFix: false, fix: '网络流量检测签名', fixed: false, layer: 1, cvss2: 4.5, cvss3: 6.7, severity: 0, component: 'cni-0.7.4', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
  { name: 'CVE-2019-002', key: 'cve_1', hasFix: true,  fix: '部署网络流量检测签名',fixed: true, layer: 2, cvss2: 4.5, cvss3: 6.7,  severity: 1, component: 'dni-0.7.5', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
  { name: 'CVE-2019-003', key: 'cve_2', hasFix: false, fix: '网络流量检测签名', fixed: false, layer: 3, cvss2: 4.5, cvss3: 6.7,  severity: 2, component: 'eni-0.7.6', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
  { name: 'CVE-2019-004', key: 'cve_3', hasFix: true,  fix: '部署网络流量检测签名', fixed: true, layer: 4, cvss2: 4.5, cvss3: 6.7,  severity: 2, component: 'fni-0.7.7', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
  { name: 'CVE-2019-005', key: 'cve_4', hasFix: false, fix: '网络流量检测签名', fixed: false, layer: 3, cvss2: 4.5, cvss3: 6.7, severity: 1, component: 'gni-0.7.8', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
  { name: 'CVE-2019-006', key: 'cve_5', hasFix: true , fix: '自动更新软件包', fixed: false, layer: 2, cvss2: 4.5, cvss3: 6.7, severity: 0, component: 'hni-0.7.9', lnk: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9946', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4' },
];

const fileData = [
  { name: 'file_001', key: 'file_0', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: false, layer: 1, severity: 0, component: '/usr/local/bin/exec', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
  { name: 'file_002', key: 'file_1', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: true, layer: 2, severity: 1, component: '/usr/local/bin/exec',  description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
  { name: 'file_003', key: 'file_2', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: false, layer: 3, severity: 2, component: '/usr/local/bin/exec', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
  { name: 'file_004', key: 'file_3', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: true, layer: 4, severity: 2, component: '/usr/local/bin/exec',  description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
  { name: 'file_005', key: 'file_4', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: false, layer: 3, severity: 1, component: '/usr/local/bin/exec', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
  { name: 'file_006', key: 'file_5', cate: 'elf', sha: 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', vt_lnk: 'https://www.virustotal.com/gui/file/ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c/detection', scanDate:'2019-10-13 00:00:01', inwhite: false, layer: 2, severity: 0, component: '/usr/local/bin/exec', description: 'Cloud Native Computing Foundation (CNCF) CNI (Container Networking Interface) 0.7.4', vt_score: {malicious: 40, benign: 10, unknown: 2} },
];

const historyData = [
  { name: '1', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_0', layer: 1, vulnerabilities: 5, description: 'RUN apk add nginx' },
  { name: '2', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_1',layer: 2, vulnerabilities: 3,  description: 'COPY /workspace /user/src/' },
  { name: '3', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_2', layer: 3, vulnerabilities: 2, description: 'RUN apk add vim' },
  { name: '4', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_3',layer: 4,  vulnerabilities: 5,  description: 'RUN apk add curl' },
  { name: '5', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_4', layer: 3, vulnerabilities: 1,  description: 'RUN apk update' },
  { name: '6', sha: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663', key: 'command_5', layer: 2, vulnerabilities: 2, description: 'FROM alpine:3.4' },
];

const packageData = [
  {key: 'package_0', name: "libacl1", source: "acl", path: "/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar", version: "2.2.52-3", vulnerabilities: 4},
  {key: 'package_1', name: "libacl2", source: "acl", path: "/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar", version: "2.2.52-3", vulnerabilities: 2},
  {key: 'package_2', name: "libacl3", source: "acl", path: "/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar", version: "2.2.52-3", vulnerabilities: 1},
  {key: 'package_3', name: "libacl4", source: "acl", path: "/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar", version: "2.2.52-3", vulnerabilities: 4},
  {key: 'package_4', name: "libacl5", source: "acl", path: "/usr/share/jenkins/jenkins.war/ant-launcher-1.9.2.jar", version: "2.2.52-3", vulnerabilities: 3},
]


function getFakeImageDetail(req, res) {
  const params = req.query;
  const { query, id } = params;
  let result = {};

  if (query === 'detail') {
    result = {
      detail: {
        name: `Image ${id}`,
        image: { key: '100', name: 'image1' },
        created: '2019-10-13 00:00:01',
        updated: '2019-10-13 00:01:01',
        owner: '管理员',
        namespace: 'dockerhub.com',
        os: 'Debian GNU/Linux 9 (stretch)',
        digest: 'sha256:73c59c460a7325ad5f62cdd3a7dd3e34a3fb16ce0140742777e1229069ace663',
        id: 'sha256:a5d38e6055d633617781f53d6bee5cb49c5c0e82f8ade135226c245eb7080df4',
        tags: ['DEVELOPMENT', 'ARKSEC'],
        status: Math.floor(Math.random() * 10) % 3,
        total: Math.floor(Math.random() * 10),
        containers: [1, 2, 3],
      },
    }
  } else if (query === 'vulns') {
    result = {
      vulns: {
        list: vulnData,
        pagination: {},
      },
    }
  } else if (query === 'files') {
    result = {
      files: {
        list: fileData,
        pagination: {},
      },
    }
  } else if (query === 'history') {
    result = {
      commands: {
        list: historyData,
        pagination: {},
      },
    }
  } else if (query === 'packages') {
    result = {
      packages: {
        list: packageData,
        pagination: {},
      },
    }
  }
  return res.json(result);
}


function postFakeList(req, res) {
  const {
    /* url = '', */
    body,
  } = req; // const params = getUrlParams(url);

  const { method, id } = body; // const count = (params.count * 1) || 20;

  let result = sourceData || [];

  switch (method) {
    case 'delete':
      result = result.filter(item => item.id !== id);
      break;

    case 'update':
      result.forEach((item, i) => {
        if (item.id === id) {
          result[i] = { ...item, ...body };
        }
      });
      break;

    case 'post':
      result.unshift({
        ...body,
        id: `fake-list-${result.length}`,
        createdAt: new Date().getTime(),
      });
      break;

    default:
      break;
  }

  return res.json(result);
}

export default {
  'GET /api/v1/detail/image': getFakeImageDetail,
  // 'POST  /api/fake_list': postFakeList,
};
