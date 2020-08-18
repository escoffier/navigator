import moment from 'moment';
// mock data
const visitData = [];
const beginDay = new Date().getTime();
const fakeY = [7, 5, 4, 2, 4, 7, 5, 6, 5, 9, 6, 3, 1, 5, 3, 6, 5];

for (let i = 0; i < fakeY.length; i += 1) {
  visitData.push({
    x: moment(new Date(beginDay + 1000 * 60 * 60 * 24 * i)).format('YYYY-MM-DD'),
    y: fakeY[i],
  });
}

const visitData2 = [];
const fakeY2 = [1, 6, 4, 8, 3, 7, 2];

for (let i = 0; i < fakeY2.length; i += 1) {
  visitData2.push({
    x: moment(new Date(beginDay + 1000 * 60 * 60 * 24 * i)).format('YYYY-MM-DD'),
    y: fakeY2[i],
  });
}

const salesData = [];

for (let i = 0; i < 12; i += 1) {
  salesData.push({
    x: `${i + 1}月`,
    y: Math.floor(Math.random() * 1000) + 200,
  });
}

const searchData = [];

for (let i = 0; i < 50; i += 1) {
  searchData.push({
    index: i + 1,
    keyword: `搜索关键词-${i}`,
    count: Math.floor(Math.random() * 1000),
    range: Math.floor(Math.random() * 100),
    status: Math.floor((Math.random() * 10) % 2),
  });
}

const salesTypeData = [
  {
    x: '家用电器',
    y: 4544,
  },
  {
    x: '食用酒水',
    y: 3321,
  },
  {
    x: '个护健康',
    y: 3113,
  },
  {
    x: '服饰箱包',
    y: 2341,
  },
  {
    x: '母婴产品',
    y: 1231,
  },
  {
    x: '其他',
    y: 1231,
  },
];
const salesTypeDataOnline = [
  {
    x: '家用电器',
    y: 244,
  },
  {
    x: '食用酒水',
    y: 321,
  },
  {
    x: '个护健康',
    y: 311,
  },
  {
    x: '服饰箱包',
    y: 41,
  },
  {
    x: '母婴产品',
    y: 121,
  },
  {
    x: '其他',
    y: 111,
  },
];
const salesTypeDataOffline = [
  {
    x: '家用电器',
    y: 99,
  },
  {
    x: '食用酒水',
    y: 188,
  },
  {
    x: '个护健康',
    y: 344,
  },
  {
    x: '服饰箱包',
    y: 255,
  },
  {
    x: '其他',
    y: 65,
  },
];
const offlineData = [];

for (let i = 0; i < 10; i += 1) {
  offlineData.push({
    name: `Stores ${i}`,
    cvr: Math.ceil(Math.random() * 9) / 10,
  });
}

const offlineChartData = [];

for (let i = 0; i < 20; i += 1) {
  offlineChartData.push({
    x: new Date().getTime() + 1000 * 60 * 30 * i,
    y1: Math.floor(Math.random() * 100) + 10,
    y2: Math.floor(Math.random() * 100) + 10,
  });
}

const titles = [
  '周期性镜像扫描任务',
  '周期性合规检测任务',
  '网络链接监测任务',
  '网络流量检测任务',
  '文件系统监测任务',
  '异常进程监测任务',
];

const avatars = [
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Apps-Winamp-icon.png', // Alipay
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Folder-OS-Configure-Alt-icon.png', // Angular
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Apps-iCloud-icon.png', // Ant Design
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Google-Docs-icon.png', // Ant Design Pro
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Other-Task-icon.png', // Bootstrap
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Folder-OS-Security-Approved-icon.png', // React
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Folder-OS-Security-icon.png', // Vue
  'http://icons.iconarchive.com/icons/igh0zt/ios7-style-metro-ui/32/MetroUI-Apps-Koding-icon.png', // Webpack
];

const avatars2 = [
  'http://icons.iconarchive.com/icons/custom-icon-design/flatastic-1/32/alert-icon.png',
  'http://icons.iconarchive.com/icons/custom-icon-design/flatastic-1/32/delete-1-icon.png',
  'http://icons.iconarchive.com/icons/custom-icon-design/flatastic-1/32/information-icon.png',
];

const getNotice = [
  {
    id: 'xxx1',
    title: titles[0],
    logo: avatars[0],
    description: '周期性扫描运行中的容器镜像并产生漏洞报告',
    updatedAt: new Date(),
    member: '上一份漏洞报告',
    href: '/policy/general',
    cate: 'image',
    memberLink: '/alerts/overview',
  },
  {
    id: 'xxx2',
    title: titles[1],
    logo: avatars[1],
    description: '周期性对集群以及容器的配置进行扫描',
    updatedAt: new Date('2019-10-24'),
    member: '上一份合规报告',
    href: '/policy/general',
    cate: 'scap',
    memberLink: '/alerts/overview',
  },
  {
    id: 'xxx3',
    title: titles[2],
    logo: avatars[2],
    description: '监测现在系统中网络链接状况',
    updatedAt: new Date(),
    member: '浏览网络链接',
    href: '/policy/general',
    cate: 'monitor',
    memberLink: '/alerts/overview',
  },
  {
    id: 'xxx4',
    title: titles[3],
    logo: avatars[3],
    description: '网络流量过滤并记录异常流量',
    updatedAt: new Date('2019-07-23'),
    member: '浏览异常流量规则',
    href: '/policy/general',
    cate: 'dpi',
    memberLink: '',
  },
  {
    id: 'xxx5',
    title: titles[4],
    logo: avatars[4],
    description: '对平台下容器进行文件系统监测',
    updatedAt: new Date(),
    member: '浏览异常文件访问',
    cate: 'host',
    href: '/policy/general',
    memberLink: '/alerts/overview',
  },
  {
    id: 'xxx6',
    title: titles[5],
    logo: avatars[5],
    description: '对平台下容器进行进程级监测',
    cate: 'docker',
    updatedAt: new Date(),
    member: '浏览容器中进程列表',
    href: '/policy/general',
    memberLink: '/alerts/overview',
  },
];
const getActivities = [
  {
    id: 'alert-1',
    updatedAt: new Date(),
    user: {
      name: 'container:nginix',
      avatar: avatars2[0],
    },
    severity: {
      name: '中等',
      avatar: avatars2[0],
      link: '',
    },
    group: {
      name: '主机监测任务',
      link: '',
    },
    project: {
      name: '[文件访问]',
      link: '',
    },
    template: '在 @{group} 中触发了 @{project}规则 警报级别[@{severity}]',
  },
  {
    id: 'alert-2',
    updatedAt: new Date(),
    user: {
      name: 'host:ml-proto',
      avatar: avatars2[1],
    },
    severity: {
      name: '严重',
      avatar: avatars2[1],
      link: '',
    },
    group: {
      name: '主机监测任务',
      link: 'http://github.com/',
    },
    project: {
      name: '[本地提权监测]',
      link: 'http://github.com/',
    },
    template: '在 @{group} 中触发了 @{project}规则 警报级别[@{severity}]',
  },
  {
    id: 'alert-3',
    updatedAt: new Date(),
    user: {
      name: 'container:nginix-production',
      avatar: avatars2[2],
    },
    severity: {
      name: '严重',
      avatar: avatars2[1],
      link: '',
    },
    group: {
      name: '网络流量监测',
      link: 'http://github.com/',
    },
    project: {
      name: '[入侵流量]',
      link: 'http://github.com/',
    },
    template: '在 @{group} 中触发了 @{project}规则 警报级别[@{severity}]',
  },
  {
    id: 'alert-4',
    updatedAt: new Date(),
    user: {
      name: 'service:nginix-deployment',
      avatar: avatars2[0],
    },
    severity: {
      name: '中等',
      avatar: avatars2[0],
      link: '',
    },
    group: {
      name: '网络流量监测',
      link: 'http://github.com/',
    },
    project: {
      name: '[异常链接]',
      link: 'http://github.com/',
    },
    template: '在 @{group} 中触发了 @{project}规则 警报级别[@{severity}]',
  },
  {
    id: 'alert-5',
    updatedAt: new Date(),
    user: {
      name: 'image:all',
      avatar: avatars2[0],
    },
    project: {
      name: '周期性镜像扫描',
      link: 'http://github.com/',
    },
    severity: {
      name: '信息',
      avatar: avatars2[2],
      link: '',
    },
    task: {
      name: '报告',
      link: '',
    },
    template: '在 @{project}中 产生新的@{task}',
  },
  {
    id: 'trend-6',
    updatedAt: new Date(),
    user: {
      name: 'containers:all',
      avatar: avatars2[2],
    },
    severity: {
      name: '信息',
      avatar: avatars2[2],
      link: '',
    },
    task: {
      name: '报告',
      link: '',
    },
    project: {
      name: '周期性合规任务',
      link: 'http://github.com/',
    },
    template: '在 @{project}中 产生新的 @{task}',
  },
];
const radarOriginData = [
  {
    name: '主机',
    ref: 10,
    koubei: 8,
    output: 4,
    contribute: 5,
    hot: 7,
  },
  {
    name: '容器',
    ref: 3,
    koubei: 9,
    output: 6,
    contribute: 3,
    hot: 1,
  },
  {
    name: '微服务集群',
    ref: 4,
    koubei: 1,
    output: 6,
    contribute: 5,
    hot: 7,
  },
];
const radarData = [];
const radarTitleMap = {
  ref: '漏洞数',
  koubei: '错误数',
  output: '动态警报数',
  contribute: '网络连接数',
  hot: '服务数',
};

radarOriginData.forEach(item => {
  Object.keys(item).forEach(key => {
    if (key !== 'name') {
      radarData.push({
        name: item.name,
        label: radarTitleMap[key],
        value: item[key],
      });
    }
  });
});

export default {
  'GET  /api/v1/stat/notice': getNotice,
  'GET  /api/v1/stat/activities': getActivities,
  'GET  /api/v1/stat/chartdata': {
    visitData,
    visitData2,
    salesData,
    searchData,
    offlineData,
    offlineChartData,
    salesTypeData,
    salesTypeDataOnline,
    salesTypeDataOffline,
    radarData,
  },
  'GET /api/v1/rest-auth/user/': {
    // pk: 2,
    // username: 'test',
    // email: 'test@arksec.io',
    // first_name: '员',
    // last_name: '测试',
    name: '管理员',
    avatar: 'http://icons.iconarchive.com/icons/oxygen-icons.org/oxygen/48/Places-user-identity-icon.png',
    userid: '00000001',
    email: 'antdesign@alipay.com',
    signature: '',
    title: '系统管理员',
    group: '事业群－平台部－技术部－DEV',
    tags: [
      {
        key: '0',
        label: '很有想法的',
      },
      {
        key: '1',
        label: '专注设计',
      },
      {
        key: '2',
        label: '辣~',
      },
      {
        key: '3',
        label: '大长腿',
      },
      {
        key: '4',
        label: '川妹子',
      },
      {
        key: '5',
        label: '海纳百川',
      },
    ],
    notifyCount: 12,
    unreadCount: 11,
    country: 'China',
    geographic: {
      province: {
        label: '浙江省',
        key: '330000',
      },
      city: {
        label: '杭州市',
        key: '330100',
      },
    },
    address: '西湖区工专路 77 号',
    phone: '0752-268888888',
  },

  'GET /api/v1/stat/overallstat': {
    statData: {
      containers: {total: 31},
      agents: {total: 2},
      images: {total: 120, inUse: 34},
      services: {total: 43},
      nodes: {total: 1}
    },
  },
};
