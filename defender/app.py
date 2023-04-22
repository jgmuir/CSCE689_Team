import lief
import pandas as pd
import random
from flask import Flask, jsonify, request
# from attribute_extractor import PEAttributeExtractor


def create_app():
    app = Flask(__name__)
    # app.config['model'] = model

    # analyse a sample
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        # if request.headers['Content-Type'] != 'application/octet-stream':
        #     resp = jsonify({'error': 'expecting application/octet-stream'})
        #     resp.status_code = 400  # Bad Request
        #     return resp

        # bytez = request.data

        # try:
        #     # initialize feature extractor with bytez
        #     # pe_att_ext = PEAttributeExtractor(bytez)
        #     # extract PE attributes
        #     atts = pe_att_ext.extract()
        #     # transform into a dataframe
        #     atts = pd.DataFrame([atts])
        #     model = app.config['model']

        #     # query the model
        #     result = model.predict_threshold(atts, threshold)[0]
        #     print('LABEL = ', result)
        # except (lief.bad_format, lief.read_out_of_bound) as e:
        #     print("Error:", e)
        #     result = 1


        # if not isinstance(result, int) or result not in {0, 1}:
        #     resp = jsonify({'error': 'unexpected model result (not in [0,1])'})
        #     resp.status_code = 500  # Internal Server Error
        #     return resp

        # resp = jsonify({'result': result})
        # resp.status_code = 200
        # return resp
        print("Hello World")

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