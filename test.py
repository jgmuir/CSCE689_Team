from modules.create_model import create_model

if __name__ == "__main__":
    model_path = "model.sav"
    sample_dir = "./samples/"
    create_model(model_path, sample_dir)