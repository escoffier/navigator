import React, { Component } from 'react';
import { FormattedMessage } from 'umi-plugin-react/locale';
import { GridContent } from '@ant-design/pro-layout';
import { Menu } from 'antd';
import { connect } from 'dva';
import BaseView from './components/base';
import SecurityView from './components/security';
import styles from './style.less';

const { Item } = Menu;

@connect(({ settingsAndagent }) => ({
  settingsAndagent,
}))
class Agent extends Component {
  main = undefined;

  constructor(props) {
    super(props);
    const menuMap = {
      cluster: (
        <FormattedMessage id="settingsandagent.menuMap.cluster" defaultMessage="Cluster" />
      ),
      agent: (
        <FormattedMessage
          id="settingsandagent.menuMap.agent"
          defaultMessage="Agent"
        />
      ),
    };
    this.state = {
      mode: 'inline',
      menuMap,
      selectKey: 'cluster',
    };
  }

  componentDidMount() {
    const { dispatch } = this.props;
    dispatch({
      type: 'settingsAndagent/fetch',
    });
    window.addEventListener('resize', this.resize);
    this.resize();
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.resize);
  }

  getMenu = () => {
    const { menuMap } = this.state;
    return Object.keys(menuMap).map(item => <Item key={item}>{menuMap[item]}</Item>);
  };

  getRightTitle = () => {
    const { selectKey, menuMap } = this.state;
    return menuMap[selectKey];
  };

  selectKey = key => {
    this.setState({
      selectKey: key,
    });
  };

  resize = () => {
    if (!this.main) {
      return;
    }

    requestAnimationFrame(() => {
      if (!this.main) {
        return;
      }

      let mode = 'inline';
      const { offsetWidth } = this.main;

      if (this.main.offsetWidth < 641 && offsetWidth > 400) {
        mode = 'horizontal';
      }

      if (window.innerWidth < 768 && offsetWidth > 400) {
        mode = 'horizontal';
      }

      this.setState({
        mode,
      });
    });
  };

  renderChildren = () => {
    const { selectKey } = this.state;

    switch (selectKey) {
      case 'cluster':
        return <BaseView />;

      case 'agent':
        return <SecurityView />;

      default:
        break;
    }

    return null;
  };

  render() {
    const { mode, selectKey } = this.state;

    return (
      <GridContent>
        <div
          className={styles.main}
          ref={ref => {
            if (ref) {
              this.main = ref;
            }
          }}
        >
          <div className={styles.leftMenu}>
            <Menu mode={mode} selectedKeys={[selectKey]} onClick={({ key }) => this.selectKey(key)}>
              {this.getMenu()}
            </Menu>
          </div>
          <div className={styles.right}>
            <div className={styles.title}>{this.getRightTitle()}</div>
            {this.renderChildren()}
          </div>
        </div>
      </GridContent>
    );
  }
}

export default Agent;
