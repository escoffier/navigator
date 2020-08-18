import React, { Component, Fragment } from 'react';


import {
    G2,
    Chart,
    Geom,
    Axis,
    Tooltip,
    Coord,
    Label,
    Legend,
    View,
    Guide,
    Shape,
    Facet,
    Util,
} from 'bizcharts';

import {
    Card,
    Button,
    Icon,
    Select, Row, Col,
} from 'antd';
import { GridContent } from '@ant-design/pro-layout';

const ButtonGroup = Button.Group;

class ComplianceTable extends Component {
    handleChange(value) {
        console.log(`Selected: ${value}`);
    }

    render() {
        const { eventClick } = this.props;
        const scaps = ['Ubuntu 主机合规', 'Kubebench 主机'];
        const children = [];
        for (let i = 0; i < 2; i++) {
            children.push(<Option key={`scap${i}`}>{scaps[i]}</Option>);
        }

        const handleChange = this.handleChange.bind(this);

        return (
            <div>
            <GridContent>
            <Row gutter={24}>
                <Col xl={10} lg={12} md={12} sm={12} xs={24}>

                        <Select
                            mode="tags"
                            placeholder="选择合规标准"
                            defaultValue={['scap0', 'scap1']}
                            onChange={handleChange}
                            style={{ width: '100%' }}
                        >
                            {children}
                        </Select>

                </Col>
                <Col xl={8} lg={12} md={12} sm={12} xs={24}>

                        <ButtonGroup>
                            <Button>显示全部</Button>
                            <Button>仅显示问题项</Button>
                        </ButtonGroup>

                </Col>

                <Col xl={6} lg={12} md={12} sm={12} xs={24}>
                    <div> 上次扫描时间 2019-10-28 10:01:01</div>
                </Col>

            </Row>
            </GridContent>
            </div>
        );
    }
}

export default ComplianceTable;
