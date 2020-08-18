// import { Card, Col, Form, List, Row, Select, Typography } from 'antd';
import { Button, Icon } from 'antd';
import React, { Component } from 'react';
import styles from './style.less';
import { FormattedMessage } from 'umi/locale';
import { connect } from 'dva';
import { InteractiveForceGraph, ForceGraphNode, ForceGraphLink, ZoomableSVGGroup } from 'react-vis-force';


@connect(({ image, loading }) => ({
  image,
  loading: loading.models.image,
}))

class Image extends Component {
    handleClick() {
      this.props.history.goBack();
    }

    componentDidMount() {
      const { dispatch } = this.props;
      dispatch({
        type: 'image/fetch',
        payload: {
          count: 5,
        },
      });
    }

    render() {
      const item = this.props.match.params;
      const {
        image: { list },
        loading,
      } = this.props;

      const handleClick = this.handleClick.bind(this);
      return (
      <div className={styles.coverCardList}>
        <Button type="primary" onClick={handleClick}>
          <Icon type="left" />
             <FormattedMessage id="image.operation.goback" />
        </Button>
        <div>
          {item.page}
          {list[item.page]? list[item.page].owner: 'no data'}
        </div>

        <InteractiveForceGraph
          simulationOptions={{ height: 500, width: 800, animate: true}}
          zoom
          labelAttr="label"
          onSelectNode={(node) => console.log(node)}
          highlightDependencies

        >
          <ForceGraphNode node={{ id: 'first-node', label: 'First node' }} r={10} fill="gray" />
          <ForceGraphNode node={{ id: 'second-node', label: 'Second node' }} r={10} fill="blue" />
          <ForceGraphNode node={{ id: 'third-node', label: 'First node' }} r={10} fill="green" />
          <ForceGraphNode node={{ id: 'fourth-node', label: 'Second node' }} r={10} fill="gray" />
          <ForceGraphLink link={{ source: 'first-node', target: 'second-node' }} />
          <ForceGraphLink link={{ source: 'first-node', target: 'third-node' }} />
          <ForceGraphLink link={{ source: 'first-node', target: 'fourth-node' }} />
        </InteractiveForceGraph>

      </div>)
    }
}

export default Image;
