from flask import Flask, request, jsonify

app = Flask(__name__)
data_storage = {"events": []}

@app.route('/services/collector/event', methods=['POST'])
def splunk_event():
    data = request.json
    data_storage["events"].append(data)
    return jsonify({"text": "Success", "code": 0}), 200

if __name__ == '__main__':
    app.run(port=8088)
