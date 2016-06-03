import os

from bottle import Bottle, run, redirect, request, response, ServerAdapter, jinja2_view
from beaker.middleware import SessionMiddleware

from urlparse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils


app = Bottle(__name__)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(__file__), 'saml')


session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './.data',
    'session.auto': True
}


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_bottle_request(req):
    url_data = urlparse(req.url)
    return {
        'https': 'on' if req.urlparts.scheme == 'https' else 'off',
        'http_host': req.get_header('host'),
        'server_port': url_data.port,
        'script_name': req.fullpath,
        'get_data': req.query,
        'post_data': req.forms,
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': req.query_string
    }


@app.route('/acs/', method='POST')
@jinja2_view('index.html', template_lookup=['templates'])
def index():
    req = prepare_bottle_request(request)
    auth = init_saml_auth(req)
    paint_logout = False
    attributes = False

    session = request.environ['beaker.session']

    auth.process_response()
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()
    if len(errors) == 0:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlSessionIndex'] = auth.get_session_index()
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.forms and self_url != request.forms['RelayState']:
            return redirect(request.forms['RelayState'])

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return {
        'errors':errors,
        'not_auth_warn':not_auth_warn,
        'attributes':attributes,
        'paint_logout':paint_logout
    }


@app.route('/', method='GET')
@jinja2_view('index.html', template_lookup=['templates'])
def index():
    req = prepare_bottle_request(request)
    auth = init_saml_auth(req)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    session = request.environ['beaker.session']

    if 'sso' in request.query:
        return_to = '{0}://{1}/'.format(request.urlparts.scheme, request.get_header('host'))
        return redirect(auth.login(return_to))
    elif 'sso2' in request.query:
        return_to = '{0}://{1}/attrs/'.format(request.urlparts.scheme, request.get_header('host'))
        return redirect(auth.login(return_to))
    elif 'slo' in request.query:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return redirect(auth.logout(name_id=name_id, session_index=session_index))
    elif 'sls' in request.query:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return {
        'errors':errors,
        'not_auth_warn':not_auth_warn,
        'success_slo':success_slo,
        'attributes':attributes,
        'paint_logout':paint_logout
    }


@app.route('/attrs/')
@jinja2_view('attrs.html', template_lookup=['templates'])
def attrs():
    paint_logout = False
    attributes = False
    session = request.environ['beaker.session']

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return {'paint_logout':paint_logout,
            'attributes':attributes}


@app.route('/metadata/')
def metadata():
    req = prepare_bottle_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        response.status = 200
        response.set_header('Content-Type', 'text/xml')
        return metadata
    else:
        response.status = 500
        return ','.join(errors)


class SSLPasteServer(ServerAdapter):
    def run(self, handler):
        from paste import httpserver

        server = httpserver.serve(handler, '0.0.0.0', '8000', ssl_pem='local.pem', start_loop=False)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    # To run HTTPS
    #run(SessionMiddleware(app, config=session_opts), host='0.0.0.0', port=8000, debug=True, reloader=True, server=SSLPasteServer)

    # To run HTTP
    run(SessionMiddleware(app, config=session_opts), host='0.0.0.0', port=8000, debug=True, reloader=True, server='paste')
