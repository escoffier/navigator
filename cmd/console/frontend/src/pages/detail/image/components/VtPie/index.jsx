import React from 'react';
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
import DataSet from '@antv/data-set';


const defaultData = {malicious: 40, benign: 10, unknown: 2};

function getData(arr) {
  return Object.keys(arr).map((key, i) => {
    return {
      item: key,
      count: arr[key],
    }
  })
}

class VtPie extends React.Component {
  render() {
    const { DataView } = DataSet;
    const { Html } = Guide;
    const data = this.props.data || defaultData;
    const tmpData = getData(data);
    const dv = new DataView();

    dv.source(tmpData).transform({
      type: 'percent',
      field: 'count',
      dimension: 'item',
      as: 'percent',
    });

    const cols = {
      percent: {
        formatter: val => {
          val = `${val * 100}%`;
          return val;
        },
      },
    };

    const totalCount = tmpData.reduce((total, item) => {
      return total + Math.round(item.count);
    }, 0);

    const htmlContent = `<div style=&quot;color:#8c8c8c;font-size:0.8em;text-align: center;width: 10em;&quot;>厂商<br><span style=&quot;color:#262626;font-size:0.8em&quot;>${totalCount}</span></div>`;
    return (
      <div>
        <Chart
          height={250}
          data={dv}
          scale={cols}
          forceFit
        >
          <Coord type="theta" radius={0.75} innerRadius={0.65} />
          <Axis name="percent" />
          <Tooltip
            showTitle={false}
            itemTpl="<li><span style=&quot;background-color:{color};&quot; class=&quot;g2-tooltip-marker&quot;></span>{name}: {value}</li>"
          />
          <Guide>
            <Html
              position={['50%', '50%']}
              html={htmlContent}
              alignX="middle"
              alignY="middle"
            />
          </Guide>
          <Geom
            type="intervalStack"
            position="percent"
            color="item"
            tooltip={[
              'item*percent',
              (item, percent) => {
                percent = `${Math.round(percent * 100)}%`;
                return {
                  name: item,
                  value: percent,
                };
              },
            ]}
            style={{
              lineWidth: 0.1,
              stroke: '#fff',
            }}
          >
            <Label
              content="percent"
              formatter={(val, item) => `${item.point.item}: ${item.point.count}`}
            />
          </Geom>
        </Chart>
      </div>
    );
  }
}

export default VtPie;
