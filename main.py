from flask import Flask, request, jsonify, abort
from flask_mongoengine import MongoEngine
from functools import wraps
import uuid
import jwt
import datetime
import os


app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'db': 'sloovi',
    'host': os.getenv('MONGO_ATLAS'),
    'port': 27017,
}
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = MongoEngine()
db.init_app(app)


class User(db.Document):
    public_id = db.StringField(max_length=100, required=True)
    first_name = db.StringField(max_length=100, required=True)
    last_name = db.StringField(max_length=100, required=True)
    email = db.StringField(required=True)
    password = db.StringField(max_length=100, required=True)

    def get_user_full_name(self):
        full_name = '{} {}'.format((self.first_name, self.last_name))
        return full_name


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers["Authorization"].split(" ")[1]

        if not token:
            error = {'message': 'a valid token is missing'}
            return jsonify(error), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.objects.get(public_id=data['public_id'])
        except:
            error = {'message': 'token is invalid'}
            return jsonify(error)

        return f(current_user, *args, **kwargs)

    return decorator


class Template(db.Document):
    template_name = db.StringField(required=True, max_length=100)
    subject = db.StringField(required=True, max_length=100)
    body = db.StringField(required=True, max_length=100)
    user = db.ReferenceField(User)


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.get_json()
    try:
        user = User.objects.get(email=auth['email'])
    except User.DoesNotExist:
        return jsonify({'message': 'User does not exist'})
    if auth['email'] != user.email and auth['password'] != user.password:
        error = {
            'message': 'could not verify',
        }
        return jsonify(error), 403

    #   users = User.query.filter_by(email=auth.get('email')).first()

    if user:
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'Message': 'Login Successful!', 'token': token})
    else:
        error = {
            'Authentication': 'login required',
            'message': 'could not verify ',
        }
        return jsonify(error), 403


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    password = data['password']
    new_user = User(public_id=str(uuid.uuid4()), first_name=data['first_name'], last_name=data['last_name'],
                    password=password, email=data['email']).save()
    data = {
        'first_name': new_user.first_name,
        'last_name': new_user.last_name,
        'email': new_user.email,
        'password': data['password'],
        'message': 'registered successfully',
    }
    return jsonify(data), 201


@app.route('/template', methods=['POST', 'GET'])
@token_required
def create_get_template(user):
    user = User.objects.get(id=user.id)
    if request.method == 'POST':
        data = request.get_json()
        template = Template(template_name=data['template_name'], body=data['body'], subject=data['subject'],
                            user=user.id).save()
        resp = {'template_name': template.template_name,
                'body': template.body,
                'subject': template.subject,
                'user': user.email
                }
        return jsonify(resp), 201
    elif request.method == 'GET':
        templates = Template.objects.filter(user=user.id)
        resp = []
        for template in templates:
            data = {'template_name': template.template_name, 'body': template.body, 'subject': template.subject,
                    'user': user.email}
            resp.append(data)
        return jsonify(resp), 200


@app.route('/template/<string:object_id>', methods=['GET', ])
def single_template(object_id):
    try:
        template = Template.objects.get(id=object_id)
    except Template.DoesNotExist:
        data = {
            'message': 'Not Found'
        }
        return jsonify(data), 404
    user = User.objects.get(id=template.user.id)
    if user:
        data = {
            "message": 'Template Retrieved successfully',
            'Body': {
                "template_name": template.template_name,
                "subject": template.subject,
                "body": template.body,
            }
        }
        return jsonify(data), 200
    else:
        return abort(403)


@app.route('/template/<string:object_id>', methods=['PUT', ])
def update_template(object_id):
    try:
        template = Template.objects.get(id=object_id)
    except Template.DoesNotExist:
        data = {
            'message': 'Not Found'
        }
        return jsonify(data), 404
    user = User.objects.get(id=template.user.id)
    if user:
        body = request.get_json()

        template.update(**body)
        data = {
            "message": 'Update successful',
            'Body': {
                "template_name": template.template_name,
                "subject": template.subject,
                "body": template.body,
            }
        }
        return jsonify(data), 200
    else:
        return abort(403)


@app.route('/template/<string:object_id>', methods=['DELETE', ])
def delete_template(object_id):
    try:
        template = Template.objects.get(id=object_id)
    except Template.DoesNotExist:
        data = {
            'message': 'Not Found'
        }
        return jsonify(data), 404
    user = User.objects.get(id=template.user.id)
    if user:
        template.delete()
        data = {
            "message": '{} deleted successfully'.format(template.template_name),
        }
        return jsonify(data), 200
    else:
        abort(403)
