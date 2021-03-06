from flask import Flask, render_template
from app.main.extensions import db, ma
from config import config 
from .main import main as main_blueprint



def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)
    ma.init_app(app)

   

    app.register_blueprint(main_blueprint)



    
    return app
