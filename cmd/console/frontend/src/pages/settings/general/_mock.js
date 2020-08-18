import city from './geographic/city.json';
import province from './geographic/province.json';

function getProvince(_, res) {
  return res.json(province);
}

function getCity(req, res) {
  return res.json(city[req.params.province]);
} // 代码中会兼容本地 service mock 以及部署站点的静态数据

export default {
  // 支持值为 Object 和 Array
  'GET  /api/user': {
    name: '管理员',
    avatar: 'http://icons.iconarchive.com/icons/oxygen-icons.org/oxygen/48/Places-user-identity-icon.png',
    userid: '00000001',
    email: 'product@example.com',
    signature: '海纳百川，有容乃大',
    title: '交互专家',
    group: '蚂蚁金服－某某某事业群－某某平台部－某某技术部－UED',
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
        label: '江苏省',
        key: '320000',
      },
      city: {
        label: '南京市',
        key: '320100',
      },
    },
    address: '江北新区研创园',
    phone: '888-8888888888',
  },
  'GET  /api/geographic/province': getProvince,
  'GET  /api/geographic/city/:province': getCity,
};
