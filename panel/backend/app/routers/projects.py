from fastapi import APIRouter
from fastapi import HTTPException
from app.models.response_models import SimpleResponse, CreateProjectResponseScheme
from app.models.request_models import CreateProjectScheme, EditProjectScheme

from app.main import g

ProjectRouter = APIRouter()


@ProjectRouter.post(
    "/createProject",
    response_description="Project successfully created",
    description="Create new project",
)
async def createProject(data: CreateProjectScheme):
    db_conn = g.db.get_conn()
    try:
        project_id, start_date = g.db.create_project(db_conn, data.title)
    finally:
        db_conn.close()

    if project_id:
        return CreateProjectResponseScheme(True, title=data.title, id=project_id, start_date=start_date)
    else:
        return SimpleResponse(False)


@ProjectRouter.post(
    "/editProject",
    response_description="Project info changed",
    description="Edit existing project",
)
async def editProject(data: EditProjectScheme):
    db_conn = g.db.get_conn()
    try:
        state = g.db.edit_project(db_conn, data.id, data.title)
    finally:
        db_conn.close()

    return SimpleResponse(state)
