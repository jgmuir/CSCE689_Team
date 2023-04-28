import io
import pefile 
import pandas as pd
import random
import winsign.verify
import time
import numpy as np
import os
from flask import Flask, jsonify, request, abort
import tempfile
from .classifier import create_classification_feature_vector
# from attribute_extractor import PEAttributeExtractor

def has_hidden_sections(pe):
    # Change the NumberOfSections to 1
    pe.FILE_HEADER.NumberOfSections = 1
    # Try to read the section, if it fails then the file isn't hiding anything
    try:
        section = pe.sections[0]
        entropy = section.get_entropy()
        return True
    except:
        return False


def create_app(model, model_thresh):
    app = Flask(__name__)
    app.config['model'] = model

    # Analyze a sample
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        print('test')
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

        bytez = request.data
        pe = pefile.PE(data=bytez)
        # Save bytez to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(bytez)
            temp_file.flush()
            temp_file.seek(0)

            # Verify the file using the winsign.verify module

            with open(temp_file, 'rb') as f:
                is_selfSigned = winsign.verify.verify_pefile(f)
                if(is_selfSigned == False):
                    resp = jsonify({'result': 1})
                    resp.status_code = 200
                    return resp
                
            # Pass the temporary file path to the create_classification_feature_vector function
            selected_feature_path = os.environ.get('SELECTED_FEATURES_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '../selected_features.txt')
            features_list = create_classification_feature_vector(temp_file.name, selected_feature_path)

           

        features_array = np.array(features_list).reshape(1, -1)
        # Load feature vector into a model and get the result
        result = app.config['model'].predict(features_array)
        # Check if file is performing section hiding by modifying NumberOfSections
        if (hasattr(pe, "FILE_HEADER")):
            if (pe.FILE_HEADER.NumberOfSections == 0):
                if has_hidden_sections(pe):
                    result = 1
                    resp = jsonify({'result': result[0]})
                    resp.status_code = 200
                    return resp

        # Get the feature vector for the current file
        selected_feature_path = os.environ.get('SELECTED_FEATURES_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '../selected_features.txt')
        features = create_classification_feature_vector(pe, selected_feature_path)
    
        # Load feature vector into a model and get the result
        result = app.config['model'].predict(features)
        #print(result)

        # Return the result
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