from app.main.extensions import db, ma


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    projects = db.relationship('Project', backref='author')

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password')

user_schema = UserSchema()
users_schema = UserSchema(many=True)


class Project(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_stories = db.Column(db.String(100))
    actions = db.relationship('Action', backref='project')



class ProjectSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'completed', 'user_id', 'user_stories')

project_schema = ProjectSchema()
projects_schema = ProjectSchema(many=True)


class Action(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    description = db.Column(db.String(200), nullable=False)
    note = db.Column(db.String(250), nullable=False)

class ActionSchema(ma.Schema):
    class Meta:
        fields = ('id', 'project_id', 'description', 'note')

action_schema = ActionSchema()
actions_schema = ActionSchema(many=True)