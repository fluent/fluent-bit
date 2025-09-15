// Copyright (C) 2019 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import {
  Button,
  Modal,
  Table,
  Card,
  TableColumnsType,
  Tooltip,
  Tag,
  Form,
  message,
  Input,
  Progress
} from "antd";
import React, { useEffect, useState } from "react";
import "antd/dist/antd.css";
import type { ColumnsType } from "antd/es/table";
import { SyncOutlined, ArrowDownOutlined } from "@ant-design/icons";
import { useSearchParams } from "react-router-dom";
const { TextArea } = Input;

const tabList2 = [
  {
    key: "error",
    tab: "error"
  },
  {
    key: "stdout",
    tab: "stdout"
  },
  {
    key: "stderr",
    tab: "stderr"
  }
];

interface ErrorDataType {
  id: number;
  name: string;
  fuzzing_id: number;
  data: any;
  status: string;
  create_time: string;
  update_time: string;
  comment: any;
}

const CardMenu: React.FC<{
  result: any;
  detail_result: any;
  tableLoading: boolean;
  resultReload: number;
  setResultReload: any;
}> = ({ result, detail_result, tableLoading, resultReload, setResultReload }) => {
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [modalVisible, setModalVisible] = useState(false);
  const [modal2Visible, setModal2Visible] = useState(false);
  const [modal3Visible, setModal3Visible] = useState(false);
  const [reloadLoading, setRelLoading] = useState(false);
  const [errorTabData, setErrorTabData] = useState("");
  const [downloadLoading, setDownLoading] = useState(false);

  result.results &&
    (result.results = result.results.map((t: any) => ({
      key: t.id,
      ...t
    })));

  const error_columns: ColumnsType<ErrorDataType> = [
    {
      title: "ErrorName",
      width: "13%",
      dataIndex: "name",
      render: (value) => {
        return (
          <Tooltip placement="topLeft" title={value}>
            <div className="col-item-value">{value}</div>
          </Tooltip>
        );
      }
    },
    {
      title: "CreateTime",
      dataIndex: "create_time",
      width: "13%",
      render: (value) => {
        return (
          <Tooltip placement="topLeft" title={value}>
            <div className="col-item-value">{value}</div>
          </Tooltip>
        );
      }
    },
    {
      title: "UpdateTime",
      dataIndex: "update_time",
      width: "13.5%",
      render: (value) => {
        return (
          <Tooltip placement="topLeft" title={value}>
            <div className="col-item-value">{value}</div>
          </Tooltip>
        );
      }
    },
    {
      title: "Comment",
      dataIndex: "comment",
      width: "12%",
      render: (value) => {
        return (
          <Tooltip placement="topLeft" title={value?.comment}>
            <div className="col-item-value">{value?.comment}</div>
          </Tooltip>
        );
      }
    },
    {
      title: "Assign",
      dataIndex: "comment",
      width: "9%",
      render: (value) => {
        return (
          <Tooltip placement="topLeft" title={value?.assign}>
            <div className="col-item-value">{value?.assign}</div>
          </Tooltip>
        );
      }
    },
    {
      title: "Status",
      dataIndex: "status",
      width: "14%",
      filters: [
        { text: "Pending", value: 2 },
        { text: "Error", value: 1 },
        { text: "OK", value: 0 }
      ],
      onFilter: (value, record) => {
        return record.status === value;
      },
      render: (value, Object) => {
        var colors: string = "";
        var val: string = "";
        if (value === 1) {
          colors = "red";
          val = `Error(${Object.name.split("-")[0]})`;
        } else if (value === 0) {
          colors = "green";
          val = "OK";
        } else if (value === 2) {
          colors = "";
          val = "pending";
        }
        return (
          <>
            {/* <Tooltip placement="topLeft" title={Object?.wamr_commit}> */}
            <div className="col-item-value">
              <Tag color={colors}> {val} </Tag>
              {/* <a
                  href={`https://github.com/bytecodealliance/wasm-micro-runtime/commit/${Object?.wamr_commit}`}
                >
                  {Object?.wamr_commit}
                </a>
              
            </Tooltip> */}
            </div>
          </>
        );
      }
    },
    {
      title: "Action",
      dataIndex: "",
      // width: "15%",
      render: (value, Object) => {
        return (
          <>
            <Button
              type="primary"
              onClick={() => {
                console.log(Object.data);
                fetch(import.meta.env.VITE_SERVER_URL + `/get_error_out?id=${Object.id}`)
                  .then((res) => {
                    return res.json();
                  })
                  .then((body) => {
                    setErrorTabData(body.result.std_out);

                    setModal3Visible(true);
                  });
              }}
            >
              Priview
            </Button>
            <Button
              key="0"
              type="link"
              onClick={async () => {
                try {
                  const response = await fetch(
                    import.meta.env.VITE_SERVER_URL + `/get_error_txt?id=${Object.id}`,
                    {
                      method: "GET"
                    }
                  );
                  console.log(Object.name);

                  get_cases(response, Object.name);
                } catch (err) {
                  message.error("Download timeout");
                }
              }}
            >
              <ArrowDownOutlined />
            </Button>
          </>
        );
      }
    }
  ];

  const onSelectChange = (newSelectedRowKeys: React.Key[]) => {
    console.log("selectedRowKeys changed: ", selectedRowKeys);
    setSelectedRowKeys(newSelectedRowKeys);
  };

  const start = (repo: string, branch: string, build_args: string) => {
    setRelLoading(true);
    fetch(import.meta.env.VITE_SERVER_URL + "/error_restart", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        id: selectedRowKeys,
        repo: repo,
        branch: branch,
        build_args: build_args
      })
    })
      .then((res) => {
        return res.json();
      })

      .then((body) => {
        setRelLoading(false);
        if (body?.status === 1) {
          setResultReload(resultReload + 1);
          message.loading("pending");
        } else {
          message.error(body?.msg ? body?.msg : "Server Error");
        }
      });
  };

  const rowSelection = {
    selectedRowKeys,
    onChange: onSelectChange,
    getCheckboxProps: (record: ErrorDataType) => ({
      disabled: Number(record.status) === 2
    })
  };
  const hasSelected = selectedRowKeys.length > 0;
  const [form] = Form.useForm();
  const set_comment = (comment: string, assign: string) => {
    setRelLoading(true);
    fetch(import.meta.env.VITE_SERVER_URL + "/set_commend", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        id: selectedRowKeys,
        comment: {
          comment: comment,
          assign: assign
        }
      })
    })
      .then((res) => {
        return res.json();
      })
      .then((body) => {
        setRelLoading(false);
        if (body?.status === 1) {
          setResultReload(resultReload + 1);
          message.success("success");
        } else {
          message.error("Server Error");
        }
      });
  };
  const get_cases = async (response: Response, name: string) => {
    try {
      if (response.headers.get("content-type") !== "application/json") {
        response
          .blob()
          .then((blob) => {
            const a = window.document.createElement("a");
            const downUrl = window.URL.createObjectURL(
              new Blob([blob], { type: "multipart/form-data" })
            );
            //定义导出文件的命名
            let filename = name;
            if (
              response.headers.get("content-disposition") &&
              response.headers?.get("content-disposition")?.indexOf("filename=") !== -1
            ) {
              filename =
                response.headers?.get("content-disposition")?.split("filename=")[1] || name;
              a.href = downUrl;
              a.download = `${decodeURI(filename.split('"')[1])}` || name;
              a.click();
              window.URL.revokeObjectURL(downUrl);
            } else {
              a.href = downUrl;
              a.download = name;
              a.click();
              window.URL.revokeObjectURL(downUrl);
            }
          })
          .catch((error) => {
            message.error(error);
          });
      } else {
        let res = await response.json();
        message.error(res.msg);
      }
    } catch (err) {
      console.log(err);
      message.error("Download timeout");
    }
  };
  return (
    <>
      <br />
      <Button></Button>
      <Card
        type={"inner"}
        style={{
          width: "100%",
          height: document.body.clientHeight - 210,
          textAlign: "left",
          borderRadius: "10px",
          overflow: "hidden"
        }}
        // headStyle={{ backgroundColor: "#87CEFAB7" }}
        title="errors"
        // extra={<a href="#">More</a>}
        // tabList={tabList}
        loading={tableLoading}
      >
        <div>
          <div
            style={{
              marginBottom: 16,
              textAlign: "left"
            }}
          >
            <Button
              loading={reloadLoading}
              type="primary"
              onClick={() => {
                setModalVisible(true);
              }}
              disabled={!hasSelected}
            >
              Verify
            </Button>
            <> </>
            <Button
              loading={reloadLoading}
              type="primary"
              onClick={() => {
                setModal2Visible(true);
              }}
              disabled={!hasSelected}
            >
              Comment
            </Button>
            <> </>
            <Button
              loading={downloadLoading}
              type="primary"
              onClick={async () => {
                setDownLoading(true);
                try {
                  const response = await fetch(import.meta.env.VITE_SERVER_URL + "/get_cases_zip", {
                    method: "POST",
                    headers: {
                      Accept: "application/json",
                      "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                      id: selectedRowKeys
                    })
                  });
                  get_cases(response, "cases.zip");
                } catch (err) {
                  message.error("Download timeout");
                }
                setSelectedRowKeys([]);
                setDownLoading(false);
              }}
              disabled={!hasSelected}
            >
              Download Selected
            </Button>
            <> </>
            <Button
              type="primary"
              icon={<SyncOutlined spin={tableLoading} />}
              onClick={() => {
                setResultReload(resultReload + 1);
              }}
            />

            <span style={{ marginLeft: 8 }}>
              {hasSelected ? `Selected ${selectedRowKeys.length} items` : ""}
            </span>
          </div>
          <Modal
            title="Priview"
            centered
            width={"60%"}
            bodyStyle={{ height: 400 }}
            visible={modal3Visible}
            footer={
              <>
                {" "}
                <Button key="close" onClick={() => setModal3Visible(false)}>
                  close
                </Button>{" "}
              </>
            }
            // onOk={() => setModal3Visible(false)}
            onCancel={() => setModal3Visible(false)}
          >
            <div
              style={{
                whiteSpace: "pre-wrap",
                height: "350px",
                overflow: "auto"
              }}
            >
              {errorTabData}
            </div>
          </Modal>
          <Modal
            title="verify"
            centered
            visible={modalVisible}
            onOk={() => {
              let repo = form.getFieldsValue(["repo", "branch", "build_args"]).repo;
              let branch = form.getFieldsValue(["repo", "branch", "build_args"]).branch;
              let build_args = form.getFieldsValue(["repo", "branch", "build_args"]).build_args;
              if (repo === "" || branch === "") {
                message.error("repo and branch cannot be empty");
                return;
              }
              if (repo === undefined) {
                repo = detail_result.repo;
              }
              if (branch === undefined) {
                branch = detail_result.branch;
              }
              if (build_args === undefined) {
                build_args = detail_result.build_args;
              }
              start(repo, branch, build_args);

              setModalVisible(false);
              setSelectedRowKeys([]);
            }}
            onCancel={() => {
              setModalVisible(false);
            }}
          >
            <Form form={form} name="domain" labelCol={{ span: 4 }} wrapperCol={{ span: 24 }}>
              <Form.Item
                label="repo"
                name="repo"
                rules={[{ required: true, message: "Please input your repo!" }]}
              >
                <TextArea defaultValue={detail_result.repo} placeholder="Please enter repo" />
              </Form.Item>
              <Form.Item
                label="branch"
                name="branch"
                rules={[{ required: true, message: "Please input your branch!" }]}
              >
                <Input defaultValue={detail_result.branch} />
              </Form.Item>
              <Form.Item label="build_args" name="build_args">
                <Input defaultValue={detail_result.build_args} placeholder="Please enter build" />
              </Form.Item>
            </Form>
          </Modal>

          <Modal
            title="Write Comment and Assign"
            centered
            visible={modal2Visible}
            onOk={() => {
              const data_any = form.getFieldsValue(["comment", "assign"]);
              const comment = data_any.comment;
              const assign = data_any.assign;
              set_comment(comment, assign);

              setModal2Visible(false);
            }}
            onCancel={() => {
              setModal2Visible(false);
            }}
          >
            <Form
              form={form}
              name="domain"
              // autoComplete="off"
              labelCol={{ span: 4 }}
              wrapperCol={{ span: 24 }}
            >
              <Form.Item label="comment" name="comment">
                <TextArea placeholder="Please enter comment" />
              </Form.Item>
              <Form.Item label="assign" name="assign">
                <Input placeholder="Please enter assign" />
              </Form.Item>
            </Form>
          </Modal>
          <Table
            bordered
            rowSelection={rowSelection}
            columns={error_columns}
            dataSource={result.results}
            scroll={{ y: document.body.clientHeight - 450 }}
          />
        </div>
      </Card>
    </>
  );
};

export default CardMenu;
