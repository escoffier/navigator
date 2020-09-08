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

function getFakeContainer(req, res) {
  const params = req.query;
  const { query, id } = params;
  let result = {};

  if (query === 'detail') {
    result = {
      detail: {
        name: `Container ${id}`,
        image: { key: '100', name: 'image1' },
        created: '2019-10-13 00:00:01',
        updated: '2019-10-13 00:01:01',
        owner: '管理员',
        namespace: 'DEV',
        tags: ['DEVELOPMENT', 'TENSORSEC'],
        status: Math.floor(Math.random() * 10) % 3,
        total: Math.floor(Math.random() * 10),
      },
    }
  } else if (query === 'logs') {
    result = {
      logs: [{ name: 'logs_test_8', key: 'log_0', created: '2019-10-13 00:00:01' },
      { name: 'logs_test_6', key: 'log_1', created: '2019-10-13 00:01:01' },
      { name: 'logs_test_7', key: 'log_2', created: '2019-10-13 00:02:01' }],
    }
  } else if (query === 'reports') {
    result = {
      reports: [{ name: 'reports_test_0', key: 'report_0', created: '2019-10-13 00:00:01' },
      { name: 'reports_test_1', key: 'report_1', created: '2019-10-13 00:01:01' },
      { name: 'reports_test_2', key: 'report_2', created: '2019-10-13 00:02:01' }],
    }
  } else if (query === 'alerts') {
    result = {
      alerts: [{ name: 'alerts_test_0', key: 'alert_0', created: '2019-10-13 00:00:01'},
      { name: 'alerts_test_1', key: 'alert_1', created: '2019-10-13 00:01:01'},
      { name: 'alerts_test_2', key: 'alert_2', created: '2019-10-13 00:02:01'}],
    }
  }

  return res.json(result);
}


export default {
  'GET /api/v1/detail/rule': getFakeContainer,
  'POST /api/v1/config/cluster': (req, res) => {
    console.log(req.body.name)
    if (req.body.name) {
      return res.status(200).json({message: `${req.body.name} 创建成功`})
    } else {
      return res.status(500).json({error: "Failed"})
    }
  },
};
