// Copyright (C) 2019 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import { useEffect, useState } from "react";
import "./App.css";

import CardMenu from "./CardMenu";
import { Divider, Typography, Col, Row, Button } from "antd";
import { Empty, Spin } from "antd";
import Description from "./Descrpition";
const { Title } = Typography;

function App() {
  const [dataList, setDataList] = useState<Array<any>>([]);
  const [results, setResults] = useState<any>({});
  const [id, setId] = useState<number>();
  const [resultReload, setResultReload] = useState<number>(0);
  const [tableLoading, setTableLoading] = useState<boolean>(false);
  const [isLoaded, setIsLoaded] = useState<boolean>(false);
  const [result, setResult] = useState<any>({});

  useEffect(() => {
    fetch(import.meta.env.VITE_SERVER_URL + "/get_list")
      .then((res) => {
        return res.json();
      })
      .then((body) => {
        setDataList(body.results);
        setIsLoaded(true);
      });
    const timer = setInterval(() => {
      fetch(import.meta.env.VITE_SERVER_URL + "/get_list")
        .then((res) => {
          return res.json();
        })
        .then((body) => {
          setDataList(body.results);
          setIsLoaded(true);
        });
    }, 3000);
  }, []);

  useEffect(() => {
    setTableLoading(true);
    fetch(import.meta.env.VITE_SERVER_URL + `/get_list?id=${id}`)
      .then((res) => {
        return res.json();
      })
      .then((body) => {
        setResults(body);
        console.log(results);
        setTableLoading(false);
      });
  }, [id, resultReload]);
  const select_uuid = {
    res: dataList,
    setId,
    setResult
  };

  if (!isLoaded) {
    return (
      <div className="App" style={{ width: document.body.clientWidth }}>
        <Spin size="large" />
      </div>
    );
  }

  if (isLoaded && !dataList) {
    return (
      <div className="App" style={{ width: document.body.clientWidth }}>
        <Empty />
      </div>
    );
  }

  return (
    <div className="App">
      <Typography>
        <br />
        <Title>WebAssembly Micro Runtime fuzzing test system</Title>
        <Divider />
      </Typography>
      <Row gutter={16}>
        <Col span={9}>
          {/* {dataList && <RunTable {...select_uuid} />} */}
          {<Description {...select_uuid} />}
        </Col>
        <Col span={15}>
          {
            <CardMenu
              {...{
                result: results,
                detail_result: result,
                tableLoading,
                resultReload,
                setResultReload
              }}
            />
          }
        </Col>
      </Row>
      <Row gutter={16}>
        <Col span={9}></Col>
      </Row>
    </div>
  );
}

export default App;
