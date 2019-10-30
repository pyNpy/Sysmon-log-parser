import flask
import yaml
from flask import jsonify, request
from elasticsearch import Elasticsearch

with open("config.yaml", "r") as yamlfile:
    config = yaml.safe_load(yamlfile)

es = Elasticsearch([{'host': config['elastic']['host'], 'port': config['elastic']['port']}])
app = flask.Flask(__name__)
app.config["DEBUG"] = True


@app.route('/search/<ide>', methods=['GET'])
def index(ide):
    results = es.get(index=config['elastic']['index'], doc_type=config['elastic']['title'], id=ide)
    return jsonify(results['_source'])


app.run()