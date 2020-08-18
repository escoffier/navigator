import React, { Component, Fragment } from 'react';

import {
  Timeline,
} from 'antd';

const colors = ['red', 'yellow', 'green'];

class EventTimeline extends Component {
  state = {
    selected: null
  };

  constructor(props) {
    super(props);
  }

  render() {
    const { data, handleItemClick, categories } = this.props;

    const itemTags = (
      <Timeline>
        {
          (data || []).map((item, key) => {
            return (
              <Timeline.Item key={item.key} color={colors[item.category||0]}>
                <a onClick={() => handleItemClick(key)}>{item.createdAt}  {item.text}</a>
                <p> {categories[item.category]} </p>
              </Timeline.Item>
            )})
        }
      </Timeline>);

    return (
      <div>
        {itemTags}
      </div>
    );
  }
}

export default EventTimeline;
