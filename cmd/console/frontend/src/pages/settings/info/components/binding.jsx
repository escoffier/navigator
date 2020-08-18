import { FormattedMessage, formatMessage } from 'umi-plugin-react/locale';
import { Icon, List, Switch, Descriptions } from 'antd';
import React, { Component, Fragment } from 'react';

class BindingView extends Component {
  getData = () => {
    const Action = (
      <Switch
        checkedChildren={formatMessage({
          id: 'settingsandinfo.settings.open',
        })}
        unCheckedChildren={formatMessage({
          id: 'settingsandinfo.settings.close',
        })}
        defaultChecked
      />
    );
    return [
      {
        title: formatMessage(
          {
            id: 'settingsandinfo.notification.password',
          },
          {},
        ),
        description: formatMessage(
          {
            id: 'settingsandinfo.notification.password-description',
          },
          {},
        ),
        actions: [Action],
      },
      {
        title: formatMessage(
          {
            id: 'settingsandinfo.notification.messages',
          },
          {},
        ),
        description: formatMessage(
          {
            id: 'settingsandinfo.notification.messages-description',
          },
          {},
        ),
        actions: [Action],
      },
      {
        title: formatMessage(
          {
            id: 'settingsandinfo.notification.todo',
          },
          {},
        ),
        description: formatMessage(
          {
            id: 'settingsandinfo.notification.todo-description',
          },
          {},
        ),
        actions: [Action],
      },
    ];
  };

  render() {
    const data = this.getData();
    return (
      <Fragment>
        <Descriptions bordered>
        <Descriptions.Item label="漏洞版本">1.1.0</Descriptions.Item>
        <Descriptions.Item label="漏洞库上次更新" span={2}>
          2019-10-24 18:00:00
        </Descriptions.Item>
        </Descriptions>
        <List
          itemLayout="horizontal"
          dataSource={data}
          renderItem={item => (
            <List.Item actions={item.actions}>
              <List.Item.Meta title={item.title} description={item.description} />
            </List.Item>
          )}
        />
      </Fragment>
    );
  }
}

export default BindingView;
