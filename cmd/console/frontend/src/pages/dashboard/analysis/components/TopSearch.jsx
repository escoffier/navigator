import { Card, Col, Icon, Row, Table, Tooltip } from 'antd';
import { FormattedMessage } from 'umi-plugin-react/locale';
import React from 'react';
import numeral from 'numeral';
import { MiniArea } from './Charts';
import NumberInfo from './NumberInfo';
import Trend from './Trend';
import styles from '../style.less';

const columns = [
  {
    title: <FormattedMessage id="dashboardandanalysis.table.rank" defaultMessage="Rank" />,
    dataIndex: 'index',
    key: 'index',
  },
  {
    title: (
      <FormattedMessage
        id="dashboardandanalysis.table.search-keyword"
        defaultMessage="Search keyword"
      />
    ),
    dataIndex: 'keyword',
    key: 'keyword',
    render: text => <a href="/">{text}</a>,
  },
  {
    title: <FormattedMessage id="dashboardandanalysis.table.containers" defaultMessage="Containers" />,
    dataIndex: 'count',
    key: 'count',
    sorter: (a, b) => a.count - b.count,
    className: styles.alignRight,
  },
  {
    title: (
      <FormattedMessage
        id="dashboardandanalysis.table.vulnerabilities"
        defaultMessage="Weekly Range"
      />
    ),
    dataIndex: 'range',
    key: 'range',
    sorter: (a, b) => a.range - b.range,
    render: (text, record) => (
        <span
          style={{
            marginRight: 4,
          }}
        >
          {text}
        </span>
    ),
  },
];

const TopSearch = ({ loading, visitData, searchData, dropdownGroup }) => (
  <Card
    loading={loading}
    bordered={false}
    title={
      <FormattedMessage
        id="dashboardandanalysis.analysis.all-vulnerabilities"
        defaultMessage="Online Top Search"
      />
    }
    extra={dropdownGroup}
    style={{
      height: '100%',
    }}
  >
    <Row gutter={68} type="flex">
      <Col
        sm={12}
        xs={24}
        style={{
          marginBottom: 24,
        }}
      >
        <NumberInfo
          subTitle={
            <span>
              <FormattedMessage
                id="dashboardandanalysis.analysis.image-vulnerabilites"
                defaultMessage="search users"
              />
              <Tooltip
                title={
                  <FormattedMessage
                    id="dashboardandanalysis.analysis.introduce"
                    defaultMessage="introduce"
                  />
                }
              >
                <Icon
                  style={{
                    marginLeft: 8,
                  }}
                  type="info-circle-o"
                />
              </Tooltip>
            </span>
          }
          gap={8}
          total={numeral(12321).format('0,0')}
          status="up"
          subTotal={17.1}
        />
        <MiniArea line height={45} data={visitData} />
      </Col>
      <Col
        sm={12}
        xs={24}
        style={{
          marginBottom: 24,
        }}
      >
        <NumberInfo
          subTitle={
            <span>
              <FormattedMessage
                id="dashboardandanalysis.analysis.criticial-vulnerabilities"
                defaultMessage="Per Capita Search"
              />
              <Tooltip
                title={
                  <FormattedMessage
                    id="dashboardandanalysis.analysis.introduce"
                    defaultMessage="introduce"
                  />
                }
              >
                <Icon
                  style={{
                    marginLeft: 8,
                  }}
                  type="info-circle-o"
                />
              </Tooltip>
            </span>
          }
          total={2.7}
          status="down"
          subTotal={12.2}
          gap={8}
        />
        <MiniArea line height={45} data={visitData} />
      </Col>
    </Row>
    <Table
      rowKey={record => record.index}
      size="small"
      columns={columns}
      dataSource={searchData}
      pagination={{
        style: {
          marginBottom: 0,
        },
        pageSize: 5,
      }}
    />
  </Card>
);

export default TopSearch;
