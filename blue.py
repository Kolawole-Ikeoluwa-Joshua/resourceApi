import os
from app import create_app
from app.main.extensions import db
from app.models import User, Project, Action, user_schema, users_schema, project_schema, projects_schema, action_schema, actions_schema
from flask_migrate import Migrate
import unittest
from flask import jsonify


app = create_app(os.environ.get('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, app=app, jsonify=jsonify, User=User, Project=Project, Action=Action, user_schema=user_schema, users_schema=users_schema, project_schema=project_schema, projects_schema=projects_schema, action_schema=action_schema, actions_schema=actions_schema)


@app.cli.command()
def test():
    """Run the unit tests. """
    
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)