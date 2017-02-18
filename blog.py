# [START all]
import os
import re
import random

import hashlib
import hmac
from string import letters

import webapp2
import jinja2
from google.appengine.ext import db

# [Start template directory]
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# [END template directory]

# [START cookie hash]
secret = 'traf'  # Secret Salt


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
# [END cookie hash]

# [START password hash]


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)
# [END password hash]

# [START input validation]
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)
# [END input validation]

# [START datastore]


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.TextProperty()
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")
# [END datastore]

# [START main request handlers]


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class BlogFront(BlogHandler):

    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


class BlogWelcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     created_by=User.by_name(self.user.name).name, likes=0,
                     liked_by=[])

            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
            pid = p.key().id()
            print "pid = ", str(pid)
            n1 = User.by_name(self.user.name).name
            print "post created by", n1
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class UpdatePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name
            print "n1 = ", n1
            print "n2 = ", n2
            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                print "post = ", post
                error = ""
                self.render("updatepost.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                self.redirect("/editDeleteError")

    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            p.subject = self.request.get('subject')
            p.content = self.request.get('content')
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
            pid = p.key().id()
            print "pid = ", str(pid)


class EditDeleteError(BlogHandler):

    def get(self):
        self.write('You can only edit or delete posts you have created.')


class DeletePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            n1 = post.created_by
            n2 = self.user.name

            if n1 == n2:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.delete()
                self.render("deletepost.html")
            else:
                self.redirect("/editDeleteError")


class LikeError(BlogHandler):

    def get(self):
        self.write("You can't like your own post & can only like a post once.")


class LikePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.created_by
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                self.redirect('/likeError')
            else:
                post.likes = post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                self.redirect('/')


class CommentError(BlogHandler):

    def get(self):
        self.write('You can only edit or delete comments you have created.')


class NewComment(BlogHandler):

    def get(self, post_id):
        if not self.user:
            error = "You must be logged in to comment"
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html", subject=subject,
                    content=content, pkey=post.key())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect('login')

        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key())
            c.put()
            self.redirect('/blog/%s' % str(post_id))

        else:
            error = "please provide a comment!"
            self.render(
                "permalink.html", post=post, content=content, error=error)


class UpdateComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("updatecomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment)
        else:
            self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            comment.delete()
            self.redirect('/blog/%s' % str(post_id))
        else:
            self.redirect('/commenterror')
# [END main request handlers]

# [START URL mapping]
app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', BlogWelcome),
                               ('/blog/([0-9]+)/updatepost', UpdatePost),
                               ('/editDeleteError', EditDeleteError),
                               ('/blog/([0-9]+)/deletepost', DeletePost),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/updatecomment/([0-9]+)',
                                UpdateComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                                DeleteComment),
                               ('/commenterror', CommentError),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/likeError', LikeError)],
                              debug=True)
# [END URL mapping]
# [END all]
