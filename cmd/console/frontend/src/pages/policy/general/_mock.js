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

function fakeList(count) {
  const list = [];

  for (let i = 0; i < count; i += 1) {
    list.push({
      key: i,
      id: `policy-${i}`,
      owner: user[i % 4],
      ownerId: `0000000${i%4}`,
      category: categories[i%5],
      name: `策略${i}`,
      updatedAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i).getTime(),
      createdAt: new Date(new Date().getTime() - 1000 * 60 * 60 * 2 * i).getTime(),
      node: `${i%6}`,
      triggers: i * 20 + 5,
      level: ['high', 'medium', 'low'][i % 3],
      entities: [],
    });
  }

  return list;
}


function getFakePolicies(req, res) {
  const params = req.query;

  let dataSource = fakeList(6);

  if (params.sorter) {
    const s = params.sorter.split('_');
    dataSource = dataSource.sort((prev, next) => {
      if (s[1] === 'descend') {
        return next[s[0]] - prev[s[0]];
      }

      return prev[s[0]] - next[s[0]];
    });
  }

  if (params.category) {
    const category = params.category.split(',');
    let filterDataSource = [];
    category.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.category === s) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.owner) {
    const owner = params.owner.split(',');
    let filterDataSource = [];
    owner.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.ownerId === s) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.node) {
    const node = params.node.split(',');
    let filterDataSource = [];
    node.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (item.node === s) {
            return true;
          }
          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }

  if (params.triggers) {
    const triggers = params.triggers.split(',');
    let filterDataSource = [];
    triggers.forEach(s => {
      filterDataSource = filterDataSource.concat(
        dataSource.filter(item => {
          if (s === '0') {
            return item.triggers <= 10;
          } else if (s === '1') {
            return item.triggers > 10 && item.triggers <= 100;
          } else if (s === '2') {
            return item.triggers > 100 && item.triggers <= 500;
          } else if (s === '3') {
            return item.triggers > 500;
          }

          return false;
        }),
      );
    });
    dataSource = filterDataSource;
  }


  return res.json(dataSource);
}

export default {
  'GET  /api/v1/profiles/policies': getFakePolicies,
};
