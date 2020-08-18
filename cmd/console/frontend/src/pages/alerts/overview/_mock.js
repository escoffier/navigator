import { parse } from 'url';

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
  '老板',
  '管理员',
  '周润发',
  '周星星',
  '',
  '',
];

function fakeList(count) {
  const list = [];

  for (let i = 0; i < count; i += 1) {
    list.push({
      key: `alert/${i}`,
      owner: user[i % 6],
      ownerId: `0000000${i % 6}`,
      category: i % 6,
      severity: [0, 1, 2, 3][i%3],
      title: titles[i % 8],
      avatar: avatars[i % 8],
      cover: parseInt(`${i / 4}`, 10) % 2 === 0 ? covers[i % 4] : covers[3 - (i % 4)],
      status: [0, 1, 2, 3][i % 4],
      taskId: (i % 4 === 1) ? `handletask/${i % 2}` : undefined,
      disabled:  (i % 4 === 0) ? false: true,
      percent: Math.ceil(Math.random() * 50) + 50,
      logo: avatars[i % 8],
      href: 'https://ant.design',
      updatedAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i),
      createdAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i),
      subDescription: desc[i % 5],
      description:
        '在中台产品的研发过程中，会出现不同的设计规范和实现方式，但其中往往存在很多类似的页面和组件，这些类似的组件会被抽离成一套标准规范。',
      activeUser: Math.ceil(Math.random() * 100000) + 100000,
      newUser: Math.ceil(Math.random() * 1000) + 1000,
      message: Math.ceil(Math.random() * 10) + 10,
      source: {name: `容器${i%6}`, key: i % 6},
      content:
        `网络产生异常流量, 源为 10.5.140.10， 目的地为 10.5.142.${i}, 扫描流量`,
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

function getFakeList(req, res) {
  const params = req.query;
  const count = params.count * 1 || 20;
  const result = fakeList(count);

  let dataSource = result;

  if (params.sorter) {
    const s = params.sorter.split('_');
    dataSource = dataSource.sort((prev, next) => {
      if (s[1] === 'descend') {
        return next[s[0]] - prev[s[0]];
      }

      return prev[s[0]] - next[s[0]];
    });
  }

  if (params.status) {
    const statuses = params.status.split(',');
    let filterDataSource = [];
    statuses.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.status === parseInt(s)) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.category) {
    const cates = params.category.split(',');
    let filterDataSource = [];
    cates.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.category === parseInt(s, 10)) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.severity) {
    const sevs = params.severity.split(',');
    let filterDataSource = [];
    sevs.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.severity === parseInt(s, 10)) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.name) {
    dataSource = dataSource.filter(data => data.content.indexOf(params.name) > -1);
  }

  if (params.ownerId) {
    dataSource = dataSource.filter(data => data.ownerId.indexOf(params.ownerId) > -1);
  }

  let pageSize = 10;

  // if (params.pageSize) {
  //   pageSize = parseInt(`${params.pageSize}`, 0);
  // }

  // const returnList = {
  //   list: dataSource,
  //   pagination: {
  //     total: dataSource.length,
  //     pageSize,
  //     current: parseInt(`${params.currentPage}`, 20) || 1,
  //   },
  // };

  return res.json(dataSource);
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
  'GET  /api/v1/alarms/alerts': getFakeList,
  'POST  /api/v1/alarms/alerts': postFakeList,
};
