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

function getLogs(vulns, date) {
  var logData = [];
  for (let i = 0; i < parseInt(vulns); i+=1) {
    logData.push({
      name: `secruity_events_${i}`,
      key: `event_${i}`,
      description: `这是一段描述${i}`,
      severity: Math.floor(Math.random() * 10) % 3,
      created: `${date} 00:0${i}:00`,
    });
  }

  return logData;
}

function getNodeScap() {
  const items = [
    {key: '2.1.1', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --allow-privileged 参数设置为 false (Scored)',
      item: '--allow-privileged',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      --allow-privileged=false\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0},
    {key: '2.1.2', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --anonymous-auth 参数设置为 false (Scored)',
      item: '--anonymous-auth',
      remediation: 'If using a Kubelet config file, edit the file to set authentication: anonymous: enabled to\n' +
          '      false .\n' +
          '      If using executable arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      --anonymous-auth=false\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.3', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --authorization-mode 参数没有设置to AlwaysAllow (Scored)',
      item: '--authorization-mode',
      remediation: 'If using a Kubelet config file, edit the file to set authorization: mode to Webhook.\n' +
          '      If using executable arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_AUTHZ_ARGS variable.\n' +
          '      --authorization-mode=Webhook\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.4', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --client-ca-file argument is set as appropriate (Scored)',
      item: '--client-ca-file',
      remediation: 'If using a Kubelet config file, edit the file to set authentication: x509: clientCAFile to\n' +
          '      the location of the client CA file.\n' +
          '      If using command line arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_AUTHZ_ARGS variable.\n' +
          '      --client-ca-file=<path/to/client-ca-file>\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 1,
    },
    {key: '2.1.5', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --read-only-port 参数设置为 0 (Scored)',
      item: '--read-only-port',
      remediation: 'If using a Kubelet config file, edit the file to set readOnlyPort to 0 .\n' +
          '      If using command line arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      --read-only-port=0\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.6', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --streaming-connection-idle-timeout 参数没有设置为0 (Scored)',
      item: '--streaming-connection-idle-timeout',
      remediation: 'If using a Kubelet config file, edit the file to set streamingConnectionIdleTimeout to a\n' +
          '      value other than 0.\n' +
          '      If using command line arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      --streaming-connection-idle-timeout=5m\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.7', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --protect-kernel-defaults 参数设置为 true (Scored)',
      item: '--protect-kernel-defaults',
      remediation: 'If using a Kubelet config file, edit the file to set protectKernelDefaults: true .\n' +
          '      If using command line arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      --protect-kernel-defaults=true\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 1,
    },
    {key: '2.1.8', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --make-iptables-util-chains 参数设置为 true (Scored)',
      item: '--make-iptables-util-chains,--make-iptables-util-chains',
      remediation: 'If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true .\n' +
          '      If using command line arguments, edit the kubelet service file\n' +
          '      $kubeletsvc on each worker node and\n' +
          '      remove the --make-iptables-util-chains argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 1,
    },
    {key: '2.1.9', audit: 'ps -fC $kubeletbin',
      object: 'kubelet', category: 'Kubebench主机合规',
      test: '确保Kubelet 配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },

    {key: '2.1.14', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保apt-get 配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },

    {key: '2.1.15', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保apt-get 配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.16', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保apt-get 配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },

    {key: '2.1.11', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保apt-get 配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
    {key: '2.1.12', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },

    {key: '2.1.13', audit: 'ps -fC $kubeletbin',
      object: 'ubuntu', category: 'Ubuntu主机合规',
      test: '确保配置 --hostname-override 参数没有设置(Scored)',
      item: '--hostname-override',
      remediation: 'Edit the kubelet service file $kubeletsvc\n' +
          '      on each worker node and remove the --hostname-override argument from the\n' +
          '      KUBELET_SYSTEM_PODS_ARGS variable.\n' +
          '      Based on your system, restart the kubelet service. For example:\n' +
          '      systemctl daemon-reload\n' +
          '      systemctl restart kubelet.service',
      result: 0,
    },
  ];

  return items
}

let tableListDataSource = [];
let tableNodeListDataSource = [];



function getContainers() {
  const tableListDataSource = []
  for (let i = 0; i < 8; i += 1) {
    tableListDataSource.push({
      key: i,
      name: `容器 ${i}`,
      title: `一个任务名称 ${i}`,
      owner: '管理员',
      image: 'nginx:latest',
      image_id: i,
      node: i % 3,
      callNo: Math.floor(Math.random() * 10),
      status: Math.floor(Math.random() * 10) % 3,
      updatedAt: new Date(`2017-07-${Math.floor(i / 2) + 1}`),
      createdAt: new Date(`2017-07-${Math.floor(i / 2) + 1}`),
      progress: Math.ceil(Math.random() * 100),
    });
  }

  return tableListDataSource;
}

function getFakeNode(req, res) {
  const params = req.query;
  const { query, id } = params;
  let result = {};

  if (query === 'detail') {
    result = {
      detail: {
        name: `节点 ${id}`,
        created: '2019-10-13 00:00:01',
        updated: '2019-10-13 00:01:01',
        owner: '管理员',
        os: 'Ubuntu: 18.04',
        kernel: '4.18',
        tags: ['DEVELOPMENT', 'ARKSEC'],
        status: 2,
      },
    }
  } else if (query === 'logs') {
    const {vulns, date} = params;
    result = {
      logs: getLogs(vulns, date),
    };
  } else if (query === 'reports') {
    result = {
      reports: getNodeScap(),
    }
  } else if (query === 'containers') {
    result = {
      containers: getContainers(),
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
  'GET /api/v1/detail/node': getFakeNode,
  // 'POST  /api/fake_list': postFakeList,
};
