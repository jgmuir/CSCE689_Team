import os
import pickle
import envparse
import pickle as cPickle
from .app import create_app
from gevent.pywsgi import WSGIServer
import gzip

# CUSTOMIZE: import model to be used
# from models.nfs_model import NeedForSpeedModel

def load_gzip_pickle(filename):
    fp = gzip.open(filename,'rb')
    obj = cPickle.load(fp)
    fp.close()
    return obj

if __name__ == "__main__":
    # retrive config values from environment variables
    model_gz_path = envparse.env("DF_MODEL_GZ_PATH", cast=str, default="models/NFS_V3.pkl.gz")
    model_thresh = envparse.env("DF_MODEL_THRESH", cast=float, default=0.7)
    model_name = envparse.env("DF_MODEL_NAME", cast=str, default="NFS_V3")
    # model_ball_thresh = envparse.env("DF_MODEL_BALL_THRESH", cast=float, default=0.25)
    # model_max_history = envparse.env("DF_MODEL_HISTORY", cast=int, default=10_000)

    # construct absolute path to ensure the correct model is loaded
    if not model_gz_path.startswith(os.sep):
        model_gz_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_gz_path)

    # CUSTOMIZE: app and model instance
    # model = load_gzip_pickle(model_gz_path)
    # # model = StatefulNNEmberModel(model_gz_path,
    #                              model_thresh,
    #                              model_ball_thresh,
    #                              model_max_history,
    #                              model_name)
    print("Test")
    app = create_app()

    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080
    print(f'Starting server on http://127.0.0.1:{port}')
 
    http_server = WSGIServer(('127.0.0.1', port), app)
    http_server.serve_forever()