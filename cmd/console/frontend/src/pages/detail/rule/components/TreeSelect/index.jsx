import { TreeSelect } from "antd";

const { TreeNode } = TreeSelect;

class TreeSelectDetail extends React.Component {
  state = {
    value: undefined
  };

  onChange = value => {
    console.log(value);
    this.setState({ value });
  };

  render() {
    return (
      <TreeSelect
        showSearch
        style={{ width: 300 }}
        value={this.state.value}
        dropdownStyle={{ maxHeight: 400, overflow: "auto" }}
        placeholder="Please select"
        allowClear
        multiple
        treeDefaultExpandAll
        onChange={this.onChange}
      >
        <TreeNode value="c-1" title="Pod容器" key="c-1">
          <TreeNode value="c-1-0" title="容器1" key="c-1-0" />
          <TreeNode value="c-1-1" title="容器2" key="c-1-1" />
          <TreeNode value="c-1-2" title="容器3" key="c-1-2" />
        </TreeNode>
        <TreeNode value="t-1" title="标签" key="t-1">
          <TreeNode
            value="t-1-0"
            title="tensorsecurity.io/install"
            key="t-1-0"
          />
          <TreeNode value="t-1-1" title="helm.chart/install" key="t-1-1" />
          <TreeNode value="t-1-2" title="develop" key="t-1-2" />
        </TreeNode>
        <TreeNode value="s-1" title="服务" key="s-1">
          <TreeNode value="s-1-0" title="Service1" key="s-1-0" />
          <TreeNode value="s-1-1" title="Service2" key="s-1-1" />
        </TreeNode>
      </TreeSelect>
    );
  }
}

export default TreeSelectDetail;
