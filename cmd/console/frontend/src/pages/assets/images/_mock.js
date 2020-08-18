import { parse } from 'url';
import moment from 'moment';
// mock tableListDataSource
let imagesDataSource = [];

const images = ['nginx', 'ubuntu', 'alpine', 'mongo', 'python'];


for (let i = 0; i < 8; i += 1) {
  const repo = images[Math.floor(Math.random() * 10) % 4]
  imagesDataSource.push({
    key: i,
    name: `${repo}: ${i}`,
    repo,
    tag: `${i}.0.0`,
    owner: '管理员',
    desc: `镜像:${repo}: ${i}的描述`,
    callNo: Math.floor(Math.random() * 1000),
    status: Math.floor(Math.random() * 10) % 2,
    updatedAt: new Date(`2019-07-${Math.floor(i / 2) + 1}`),
    createdAt: new Date(`2019-07-${Math.floor(i / 2) + 1}`),
    sha: `sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f${i}${i}${i}0`,
    vulnerabilities: [
      {key: 0, number:  Math.floor(Math.random() * 100) % 8},
      {key: 1, number:  Math.floor(Math.random() * 100) % 6},
      {key: 2, number:  Math.floor(Math.random() * 100) % 6},
      ],
    });
}

function getImages(req, res, u) {
  let url = u;

  if (!url || Object.prototype.toString.call(url) !== '[object String]') {
    // eslint-disable-next-line prefer-destructuring
    url = req.url;
  }

  const params = parse(url, true).query;
  let dataSource = imagesDataSource;

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
    const status = params.status.split(',');
    let filterDataSource = [];
    status.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (parseInt(`${item.status}`, 10) === parseInt(s.split('')[0], 10)) {
            return true;
          }

          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.name) {
    dataSource = dataSource.filter(data => data.name.indexOf(params.name) > -1);
  }

  if (params.sha) {
    dataSource = dataSource.filter(data => data.sha.indexOf(params.sha) > -1);
  }

  if (params.date) {
    dataSource = dataSource.filter(data => {
      return true;
      // const requiredDate = moment(params.date);
      // return (requiredDate.isBefore(data.updatedAt));
    })
  }

  let pageSize = 10;

  if (params.pageSize) {
    pageSize = parseInt(`${params.pageSize}`, 0);
  }

  const result = {
    list: dataSource,
    pagination: {
      total: dataSource.length,
      pageSize,
      current: parseInt(`${params.currentPage}`, 10) || 1,
    },
  };
  return res.json(result);
}

function postImages(req, res, u, b) {
  let url = u;

  if (!url || Object.prototype.toString.call(url) !== '[object String]') {
    // eslint-disable-next-line prefer-destructuring
    url = req.url;
  }

  const body = (b && b.body) || req.body;
  const { method, name, desc, key } = body;

  switch (method) {
    /* eslint no-case-declarations:0 */
    case 'delete':
      imagesDataSource = imagesDataSource.filter(item => key.indexOf(item.key) === -1);
      break;

    case 'post':
      const i = Math.ceil(Math.random() * 10000);
      imagesDataSource.unshift({
        key: i,
        name: `${repo}: ${i}`,
        repo,
        owner: '管理员',
        desc: `镜像:${repo}: ${i}的描述`,
        callNo: Math.floor(Math.random() * 1000),
        status: Math.floor(Math.random() * 10) % 2,
        updatedAt: new Date(`2019-07-${Math.floor(i / 2) + 1}`),
        createdAt: new Date(`2019-07-${Math.floor(i / 2) + 1}`),
        vulnerabilities: {
          critical: Math.floor(Math.random() * 10) % 6,
          medium: Math.floor(Math.random() * 10) % 4,
          low: Math.floor(Math.random() * 10) % 4,
        },
      });
      break;

    case 'update':
      imagesDataSource = imagesDataSource.map(item => {
        if (item.key === key) {
          return { ...item, desc, name };
        }

        return item;
      });
      break;

    default:
      break;
  }

  const result = {
    list: imagesDataSource,
    pagination: {
      total: imagesDataSource.length,
    },
  };
  return res.json(result);
}

export default {
  'GET /api/v1/assets/images': getImages,
  'POST /api/v1/assets/images': postImages,
};
