import hashlib
import os
import secrets

from fastapi import HTTPException


def authorize(request, policy):
    if not policy['enabled']:
        return {'name': 'local', 'role': 'admin'}
    if request.url.scheme != 'https' and (not request.client or request.client.host not in ('127.0.0.1', '::1')):
        raise HTTPException(400, 'Remote authenticated access requires HTTPS')
    scheme, _, token = request.headers.get('authorization', '').partition(' ')
    identity = None
    if scheme.lower() == 'bearer' and 32 <= len(token) <= 512:
        supplied = hashlib.sha256(token.encode()).digest()
        for user in policy['users']:
            expected = os.getenv(user['token_env'], '')
            if len(expected) >= 32 and secrets.compare_digest(supplied, hashlib.sha256(expected.encode()).digest()):
                identity = {'name': user['name'], 'role': user['role']}
    if identity is None:
        raise HTTPException(401, 'A valid access token is required', headers={'WWW-Authenticate': 'Bearer'})
    role, path = identity['role'], request.url.path
    if path == '/api/session':
        return identity
    if role == 'sensor':
        allowed = request.method == 'POST' and path == '/api/endpoint-events'
    elif path == '/api/exports':
        allowed = role in ('viewer', 'analyst', 'admin')
    elif request.method in ('GET', 'HEAD'):
        allowed = role in ('viewer', 'analyst', 'admin') and (path != '/api/config' or role == 'admin')
    elif path in ('/api/train', '/api/capture', '/api/context/refresh'):
        allowed = role == 'admin'
    else:
        allowed = role in ('analyst', 'admin')
    if not allowed:
        raise HTTPException(403, 'This access token does not permit this operation')
    return identity
