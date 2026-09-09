import uvicorn

from backend.app.config import settings

if __name__ == '__main__':
    config = settings()['app']['app']
    uvicorn.run('backend.app.main:app', host=config['host'], port=config['port'])
