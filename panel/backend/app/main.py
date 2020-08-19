from fastapi import FastAPI, HTTPException, Depends
import uvicorn
from app.interactors.globals import Globals
g = Globals()
import app.routers.configure as conf_r
import app.routers.projects as proj_r
from app.interactors.db import MySQLClient

env = 'dev'


def bilbo_baggins():
    if not g.google_api:
        raise HTTPException(status_code=403, detail="Google Compute Cloud token is not set yet.")


def main():
    g.db = MySQLClient('127.0.0.1', 'nobody', 'paseca', 'webstress_test')

    docs_kwargs = {}
    if env == 'prod':
        docs_kwargs = dict(docs_url=None, redoc_url=None)

    app = FastAPI(**docs_kwargs)
    app.include_router(conf_r.CFGRouter)
    app.include_router(proj_r.ProjectRouter, dependencies=[Depends(bilbo_baggins)])

    uvicorn.run(app, host='127.0.0.1', port=5000, log_level='info')
