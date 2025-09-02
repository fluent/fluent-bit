// Copyright (C) 2019 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import {
  Descriptions,
  DatePicker,
  Card,
  Space,
  Button,
  Badge,
  Divider,
  Row,
  Statistic,
  Col,
  Modal,
  Form,
  Input,
  message,
  Upload,
  UploadFile
} from "antd";
import { useEffect, useState } from "react";
import moment from "moment";
import "antd/dist/antd.css";
import { UploadOutlined } from "@ant-design/icons";
import type { DatePickerProps, RangePickerProps } from "antd/es/date-picker";
const { TextArea } = Input;
interface DataType {
  id: number;
  branch: string;
  build_args: string;
  start_time: string;
  end_time: string;
  status: string;
  repo: string;
  data: any;
  wamr_commit: string;
  fuzz_time: number;
  end_error: number;
  error: number;
}

interface select_uuid {
  res: Array<DataType>;
  setId: any;
  setResult: any;
}
const normFile = (e: any) => {
  console.log("Upload event:", e);
  if (Array.isArray(e)) {
    return e;
  }
  return e?.fileList;
};
const Description = ({ res, setId, setResult }: select_uuid) => {
  // const formRef = react
  const range = (start: number, end: number) => {
    const result = [];
    for (let i = start; i < end; i++) {
      result.push(i);
    }
    return result;
  };
  const [modalVisible, setModalVisible] = useState<boolean>(false);
  const [modal2Visible, setModal2Visible] = useState<boolean>(false);
  const [form] = Form.useForm();
  // const [fileList, setFileList] = useState<UploadFile[]>([]);
  const disabledDate: RangePickerProps["disabledDate"] = (current) => {
    return current && current < moment().subtract(1, "day").endOf("day");
  };
  // let fileList: UploadFile[] = [];
  var fileList: Array<string> = [];
  const new_fuzzing = (repo: string, branch: string, fuzz_time: number, build_args: string) => {
    fetch(import.meta.env.VITE_SERVER_URL + "/new_fuzzing", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        repo: repo,
        branch: branch,
        fuzz_time: fuzz_time,
        build_args: build_args
      })
    })
      .then((res) => {
        return res.json();
      })
      .then((body) => {
        if (body.status === 0) {
          message.error(body.msg);
        } else {
          message.success("new fuzzing success");
        }
      });
  };
  return (
    <>
      <Row gutter={16}>
        <Col span={5}>
          <Button
            type="primary"
            style={{}}
            onClick={() => {
              setModalVisible(true);
            }}
          >
            New fuzzing test
          </Button>
        </Col>
        <> </>
        <Col span={8}>
          <Button
            type="primary"
            style={{}}
            onClick={() => {
              setModal2Visible(true);
            }}
          >
            Upload Case
          </Button>
        </Col>
      </Row>
      <Modal
        title="Write Comment and Assign"
        centered
        visible={modalVisible}
        onOk={() => {
          const fields_value = form.getFieldsValue(["repo", "branch", "end_time", "build_args"]);
          let repo = fields_value.repo;
          let branch = fields_value.branch;
          let fuzz_time = fields_value.end_time;
          const build_args = fields_value.build_args;

          if (repo !== "" || branch !== "") {
            repo =
              repo === undefined
                ? "https://github.com/bytecodealliance/wasm-micro-runtime.git"
                : repo;
            branch = branch === undefined ? "main" : branch;

            if (fuzz_time) {
              const this_time = Date.parse(new Date().toString());
              fuzz_time = Date.parse(fuzz_time);
              if (fuzz_time > this_time) {
                fuzz_time = (fuzz_time - this_time) / 1000;
              } else {
                fuzz_time = 1;
              }
            }
            new_fuzzing(repo, branch, fuzz_time, build_args);
            setModalVisible(false);
          } else {
            message.error("please enter repo and branch");
          }
        }}
        onCancel={() => {
          setModalVisible(false);
        }}
      >
        <Form
          form={form}
          name="domain"
          // autoComplete="off"
          labelCol={{ span: 4 }}
          wrapperCol={{ span: 24 }}
          initialValues={{ remember: true }}
        >
          <Form.Item
            label="repo"
            name="repo"
            rules={[{ required: true, message: "Please input your repo!" }]}
          >
            <TextArea
              defaultValue="https://github.com/bytecodealliance/wasm-micro-runtime.git"
              placeholder="Please enter repo"
            />
          </Form.Item>
          <Form.Item
            label="branch"
            name="branch"
            rules={[{ required: true, message: "Please input your branch!" }]}
          >
            <Input defaultValue="main" placeholder="Please enter branch" />
          </Form.Item>
          <Form.Item label="end_time" name="end_time">
            <DatePicker
              format="YYYY-MM-DD HH:mm:ss"
              disabledDate={disabledDate}
              // disabledTime={disabledDateTime}
              showTime={{ defaultValue: moment("00:00:00", "HH:mm:ss") }}
            />
          </Form.Item>
          <Form.Item label="build_args" name="build_args">
            <Input placeholder="Please enter build_args" />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="Upload Cases"
        footer={[]}
        onCancel={() => {
          form.resetFields();
          setModal2Visible(false);
        }}
        onOk={() => {
          // console.log(123123, fileList);
          form.resetFields();
          setModal2Visible(false);
        }}
        visible={modal2Visible}
      >
        <Form
          form={form}
          name="upload"
          // action={import.meta.env.VITE_SERVER_URL + "/uplad_case"}
          // method="post"
          // encType="multipart/form-data"
          autoComplete="off"
          labelCol={{ span: 4 }}
          wrapperCol={{ span: 24 }}
          initialValues={{ remember: true }}
        >
          <Form.Item
            name="upload"
            label="upload"
            valuePropName="fileList"
            getValueFromEvent={normFile}
          >
            {/* <input type="file" /> */}
            <Upload
              name="file"
              listType="picture"
              action={import.meta.env.VITE_SERVER_URL + "/upload_case"}
              // action=""
              // fileList={fileList}
              beforeUpload={(file) => {
                return new Promise((resolve, reject) => {
                  let fileName = file.name;
                  const file_config = fileName.split(".");
                  if (file_config[file_config.length - 1] !== "wasm") {
                    message.error("Wrong file type");
                    return reject(false);
                  }
                  return resolve(true);
                });
              }}
              onRemove={(file) => {
                // import.meta.env.VITE_SERVER_URL + "/remove_case"
                // console.log(file.name);
                fetch(import.meta.env.VITE_SERVER_URL + "/remove_case", {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/json"
                  },

                  body: JSON.stringify({
                    filename: file.name
                  })
                });
              }}
            >
              <Button icon={<UploadOutlined />}>Click to upload</Button>
            </Upload>
          </Form.Item>
        </Form>
      </Modal>
      <br />
      <Space
        direction="vertical"
        size="middle"
        style={{
          display: "flex",
          height: document.body.clientHeight - 210,
          overflow: "auto"
        }}
      >
        {Object.keys(res).map((r: any) => (
          <Card
            type="inner"
            title={res[r].repo + ": " + res[r].branch}
            style={{
              width: "99.9%",
              textAlign: "left",
              borderRadius: "10px",
              overflow: "hidden"
            }}
            headStyle={{ backgroundColor: "#87CEFAB7" }}
          >
            <Descriptions
              size="default"
              column={2}
              // title={"pid: " + (res[r].data?.pid ? res[r].data?.pid : "")}
              extra={
                Number(res[r].status) === 2 ? (
                  res[r].data?.error ? (
                    <Badge status="error" text={res[r].data?.error} />
                  ) : (
                    <Badge status="processing" text="to be operated" />
                  )
                ) : Number(res[r].status) === 1 ? (
                  <Badge status="processing" text="Running" />
                ) : (
                  <Badge status="default" text="End" />
                )
              }
            >
              <Descriptions.Item label="Start time">{res[r].start_time}</Descriptions.Item>
              <Descriptions.Item label="End time">{res[r].end_time}</Descriptions.Item>
              <Descriptions.Item label="Build args">{res[r].build_args}</Descriptions.Item>
              <Descriptions.Item label="WAMR commit">
                <a
                  href={`https://github.com/bytecodealliance/wasm-micro-runtime/commit/${res[r]?.wamr_commit}`}
                >
                  {res[r]?.wamr_commit}
                </a>
              </Descriptions.Item>

              <Descriptions.Item label="">
                <Row gutter={24}>
                  <Col span={10}>
                    <Button
                      type="primary"
                      onClick={() => {
                        setId(res[r].id);
                        setResult(res[r]);
                      }}
                    >
                      Detail
                    </Button>
                  </Col>
                  <Col span={10}>
                    <Button
                      disabled={Number(res[r].status) !== 1}
                      type="primary"
                      danger
                      onClick={() => {
                        fetch(import.meta.env.VITE_SERVER_URL + "/end_fuzzing", {
                          method: "POST",
                          headers: {
                            Accept: "application/json",
                            "Content-Type": "application/json"
                          },

                          body: JSON.stringify({
                            id: res[r].id
                          })
                        })
                          .then((res) => {
                            return res.json();
                          })
                          .then((body) => {
                            if (body.status === 0) {
                              message.error(body.msg);
                            } else {
                              message.success("Stop fuzzing success");
                            }
                          });
                      }}
                    >
                      Stop
                    </Button>
                  </Col>
                </Row>
              </Descriptions.Item>
            </Descriptions>
            <Divider />

            <Row gutter={24}>
              <Col span={6}>
                <Statistic title="Total Error" value={res[r].error + res[r].end_error} />
              </Col>
              <Col span={6}>
                <Statistic title="Fixed" value={res[r].end_error} />
              </Col>
              <Col span={8}>
                <Statistic title="Remaining Errors" value={res[r].error} />
              </Col>
            </Row>
          </Card>
        ))}
      </Space>
    </>
  );
};

export default Description;
