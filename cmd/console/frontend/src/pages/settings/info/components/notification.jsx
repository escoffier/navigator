import { List, Switch, Upload, Table, Button } from 'antd';
import React, { Component, Fragment } from 'react';
import { formatMessage } from 'umi-plugin-react/locale';

class NotificationView extends Component {

  render() {
    const scaps = [{
      key: 0,
      name: 'CIS-linux-Bench',
      desc: '针对Linux系统的检查',
      updated: '2019/10/24, 3:24:00 AM'
    },{
      key: 1,
      name: 'CIS-Kubernetes-Bench',
      desc: '针对Kubernetes系统的检查',
      updated: '2019/10/24, 3:24:00 AM'
    },{
      key: 2,
      name: 'CIS-Docker-Bench',
      desc: '针对Dokcer系统的检查',
      updated: '2019/10/24, 3:24:00 AM'
    },
    ];

    const columns = [
      {
        title: '基准名称',
        dataIndex: 'name',
        key: 'name',
      }, {
        title: '描述',
        dataIndex: 'desc',
      },
      {
        title: '更新时间',
        dataIndex: 'updated',
      },
    ];
    return (
      <Fragment>
        <Upload fileList={[]}>
          <div>(支持SCAP/XCCDF文件格式)
          </div>
          <div>
            <Button icon="upload">
              上传新基准文件
            </Button>
          </div>
        </Upload>
        <Table
          dataSource={scaps}
          columns={columns}
        />
      </Fragment>
    );
  }
}

export default NotificationView;
