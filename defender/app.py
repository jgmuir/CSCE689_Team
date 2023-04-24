import io
import pefile
import pandas as pd
import random
import os
from flask import Flask, jsonify, request, abort
from .classifier import create_classification_feature_vector
# from attribute_extractor import PEAttributeExtractor


def create_app(model, model_thresh):
    app = Flask(__name__)
    app.config['model'] = model

    # analyse a sample
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

      
        bytez = request.data
        selected_feature_path = selected_feature_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../selected_features.txt')
        selected_feature_path = os.environ['SELECTED_FEATURES_PATH']

        features = create_classification_feature_vector(bytez, selected_feature_path)
    
        # load feature vector into a model and get the result
        result = app.config['model'].predict(features)
        resp = jsonify({'result': result[0]})
        resp.status_code = 200
        return resp
    # get the model info
    @app.route('/model', methods=['GET'])
    def get_model():
        # curl -XGET http://127.0.0.1:8080/model
        resp = jsonify(app.config['model'].model_info())
        resp.status_code = 200
        return resp

    # return a value that is 1 or 0 randomly
    @app.route('/random', methods=['GET'])
    def get_random():
        # curl -XGET http://127.0.0.1:8080/random
        resp = jsonify({'result': random.randint(0, 1)})
        resp.status_code = 200
        return resp
    return app

# if __name__ == '__main__':
#     app = create_app()
#     app.run(host='0.0.0.0', port=8080, debug=True)