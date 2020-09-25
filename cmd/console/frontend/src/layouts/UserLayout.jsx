import {
  DefaultFooter,
  getMenuData,
  getPageTitle
} from "@ant-design/pro-layout";
import DocumentTitle from "react-document-title";
import Link from "umi/link";
import React from "react";
import { connect } from "dva";
import { formatMessage } from "umi-plugin-react/locale";
import SelectLang from "@/components/SelectLang";
import logo from "../assets/logo.svg";
import styles from "./UserLayout.less";

const UserLayout = props => {
  const mylinks = [
    {
      key: "container-log",
      title: "探真科技网络公司",
      href: "http://tensorsecurity.io",
      blankTarget: true
    }
  ];

  const {
    route = {
      routes: []
    }
  } = props;
  const { routes = [] } = route;
  const {
    children,
    location = {
      pathname: ""
    }
  } = props;
  const { breadcrumb } = getMenuData(routes);
  return (
    <DocumentTitle
      title={getPageTitle({
        pathname: location.pathname,
        breadcrumb,
        formatMessage,
        ...props
      })}
    >
      <div className={styles.container}>
        <div className={styles.lang}>
          <SelectLang />
        </div>
        <div className={styles.content}>
          <div className={styles.top}>
            <div className={styles.header}>
              <Link to="/">
                <img alt="logo" className={styles.logo} src={logo} />
                <span className={styles.title}>探真科技网络公司</span>
              </Link>
            </div>
            <div className={styles.desc}></div>
          </div>
          {children}
        </div>
        <DefaultFooter copyright="南京尓嘉网络科技有限公司" links={mylinks} />
      </div>
    </DocumentTitle>
  );
};

export default connect(({ settings }) => ({ ...settings }))(UserLayout);
