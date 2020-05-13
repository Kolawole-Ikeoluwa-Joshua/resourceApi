from . import main
from .extensions import db
from ..models import User, Project, Action, user_schema, users_schema, project_schema, projects_schema, action_schema, actions_schema
from flask import request, jsonify, make_response, redirect, url_for, render_template, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import datetime, jwt
from functools import wraps
from sqlalchemy import or_
import os





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is missing'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@main.route('/api/users/register', methods=['POST'])
def reg_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    if User.query.filter_by(username=new_user.username).first():
        return make_response('Registration Completed',200)


@main.route('/api/users', methods=['GET'])
def get_all_users():

    users = User.query.all()

    """output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'users': output})"""

    return jsonify(users_schema.dump(users)),200

   

@main.route('/api/users/auth')
def user_auth():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        
        
        token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, current_app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Invalid Password Entry', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@main.route('/api/projects', methods=['POST'])
@token_required
def create_project(current_user):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    data = request.get_json()
    new_project = Project(name=data['name'], description=data['description'], completed=data['completed'], user_id=current_user.id, user_stories='None')
    db.session.add(new_project)
    db.session.commit()
    return make_response('Project Added', 200)
    





@main.route('/api/projects', methods=['GET'])
@token_required
def get_all_projects(current_user):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    args = request.args
    offset = 0
    
    limit = 10
    if "offset" in args:
        offset = args['offset']

    if "limit" in args:
        limit = args['limit']

    


    if "search" in args:
        searchParameters = args["search"]
        

        results = Project.query.filter(or_(Project.name.like('%' + searchParameters + '%'), Project.description.like('%' + searchParameters + '%'))).offset(offset).limit(limit).all()
        

        return jsonify(projects_schema.dump(results)), 200
    

    projects = Project.query.offset(offset).limit(limit).all()
    return jsonify(projects_schema.dump(projects)), 200  
    


@main.route('/api/projects/<project_id>', methods=['GET'])
@token_required
def get_one_project(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:
        return project_schema.jsonify(project)
    return make_response('Project Not Found!', 404)


@main.route('/api/projects/<project_id>', methods=['PUT'])
@token_required
def update_project(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:
        data = request.get_json()
        project.name = data['name']
        project.description = data['description']
        project.completed = data['completed']
        db.session.commit()

        return make_response('Project Updated', 200)
    return make_response('Project Not Found!', 404)


@main.route('/api/projects/<project_id>', methods=['PATCH'])
@token_required
def update_property(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:
        data = request.get_json()
        
        project.completed = data['completed']
        db.session.commit()

        return make_response('Completed Property Updated', 200)
    return make_response('Project Not Found!', 404)


@main.route('/api/projects/<project_id>', methods=['DELETE'])
@token_required
def delete_project(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:
        db.session.delete(project)
        db.session.commit()

        return make_response('Project Deletion Successful', 200)
    return make_response('Project Not Found!', 404)



@main.route('/api/projects/<project_id>/actions', methods=['POST'])
@token_required
def new_action(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:

        data = request.get_json()
        description = data['description']
        note = data['note']
        action = Action(project_id=project.id, description=description, note=note)
        db.session.add(action)
        db.session.commit()
        return make_response(f'Action Completed for Project: {project_id}', 200)

    return make_response('Project Not Found', 404)


@main.route('/api/actions', methods=['GET'])
@token_required
def get_all_actions(current_user):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    actions = Action.query.all()
    return jsonify(actions_schema.dump(actions)), 200


@main.route('/api/projects/<project_id>/actions', methods=['GET'])
@token_required
def get_project_action(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    if project:

        actions = Action.query.filter_by(project_id=project.id)
    
        return jsonify(actions_schema.dump(actions))
        
    return make_response('Project Not Found', 404)



@main.route('/api/actions/<action_id>', methods=['GET'])
@token_required
def get_action_by_id(current_user, action_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    action = Action.query.filter_by(id=action_id).first()
    if action:
    
        return action_schema.jsonify(action), 200
        
    return make_response('Action Not Found', 404)



@main.route('/api/projects/<project_id>/actions/<action_id>', methods=['GET'])
@token_required
def get_proaction_by_id(current_user, project_id, action_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    action = Action.query.filter_by(id=action_id).first()

    if project and action:

        result = Action.query.filter_by(project_id=project.id).all()

        for i in result:
            if i.id == action.id:

                return  action_schema.jsonify(i), 200


    return make_response('Project or Action Not Found', 404)


@main.route('/api/projects/<project_id>/actions/<action_id>', methods=['PUT'])
@token_required
def upd_proaction_by_id(current_user, project_id, action_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    action = Action.query.filter_by(id=action_id).first()
    data = request.get_json()

    if project and action:

        result = Action.query.filter_by(project_id=project.id).all()

        for i in result:
            if i.id == action.id:
                if data['description'] and data['note']:
                    i.description = data['description']
                    i.note = data['note']
                    db.session.commit()
                    return make_response('Action Updated!', 200)

                return make_response('Invalid Entry', 401)
                    
          
    return make_response('Project or Action Not Found', 404)


@main.route('/api/projects/<project_id>/actions/<action_id>', methods=['DELETE'])
@token_required
def delete_proaction_by_id(current_user, project_id, action_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    project = Project.query.filter_by(id=project_id).first()
    action = Action.query.filter_by(id=action_id).first()
    
    if project and action:

        result = Action.query.filter_by(project_id=project.id).all()

        for i in result:
            if i.id == action.id:
                db.session.delete(i)
                db.session.commit()

                return make_response('Deletion Successful!', 200)
                
    return make_response('Project or Action Not Found', 404)


@main.route('/api/projects/<project_id>')
@token_required
def index(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    return render_template('upload.html')

    

@main.route('/api/projects/<project_id>/upload', methods=['PUT'])
@token_required
def upload(current_user, project_id):

    if not current_user:
        return make_response('Please Login in to proceed', 401)

    if request.method == 'PUT':
        # check if the post request has the file part
        if 'file' not in request.files:
            return make_response('no file present', 404)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return make_response('no file present', 404)
        if file and file.filename:
            filename = secure_filename(file.filename)
            filePath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(filePath)

            project = Project.query.filter_by(id=project_id).first()
            if project:
                 project.user_stories = filePath

                 db.session.commit()

                 return make_response('User Files Uploaded', 200)

            return make_response('Project Not found', 404)


            
        

    