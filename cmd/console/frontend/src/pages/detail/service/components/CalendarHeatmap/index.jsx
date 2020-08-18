import React, { Component, Fragment } from 'react';
import { data } from './data';

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


class CalendarHeatmap extends Component {
  render() {
    const cols = {
      day: {
        type: 'cat',
        values: [
          '星期日',
          '星期一',
          '星期二',
          '星期三',
          '星期四',
          '星期五',
          '星期六',
        ],
      },
      week: {
        type: 'cat',
      },
      commits: {
        sync: true,
      },
    };
    return (
      <div>
        <Chart
          height={400}
          data={data}
          scale={cols}
          forceFit
        >
          <Tooltip title="date" />
          <Axis
            name="week"
            position="top"
            tickLine={null}
            line={null}
            label={{
              offset: 12,
              textStyle: {
                fontSize: 12,
                fill: '#666',
                textBaseline: 'top',
              },
              formatter: val => {
                if (val === '2') {
                  return '五月';
                } if (val === '6') {
                  return '六月';
                } if (val === '10') {
                  return '七月';
                } if (val === '15') {
                  return '八月';
                } if (val === '19') {
                  return '九月';
                } if (val === '24') {
                  return '十月';
                }

                return '';
              },
            }}
          />
          <Axis name="day" grid={null} />
          <Geom
            type="polygon"
            position="week*day*date"
            color={['vulns', '#BAE7FF-#1890FF-#0050B3']}
          />
          <Coord reflect="y" />
        </Chart>
      </div>
    );
  }
}

export default CalendarHeatmap;
