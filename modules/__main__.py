import sys
import os
import pickle
from modules.apps import create_app
from gevent.pywsgi import WSGIServer

from modules.create_model import create_model

if __name__ == "__main__":
    model_path = "model.sav"
    sample_dir = "./samples/"
    create_model(model_path, sample_dir)
    model_thresh = 0.7
    if not model_path.startswith(os.sep):
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_path)
    model = pickle.load(model_path)
    app = create_app(model, model_thresh)
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()