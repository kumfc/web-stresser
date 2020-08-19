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


@ProjectRouter.post(
    "/getProject",
    response_description="Includes project info",
    description="Request detailed project info"
)
async def getProject():
    ...


@ProjectRouter.post(
    "/getAttack",
    response_description="Includes attack info",
    description="Request detailed attack info"
)
async def getAttack():
    ...


@ProjectRouter.post(
    "/finishProject",
    response_description="Project closed",
    description="Finish existing project"
)
async def finishProject():
    ...


@ProjectRouter.post(
    "/addAttack",
    response_description="New attack started",
    description="Start new attack in existing project"
)
async def addAttack():
    # TODO check if finished
    # TODO check if attack is already running
    ...

@ProjectRouter.post(
    "/finishAttack",
    response_description="Attack has been stopped",
    description="Finish an attack"
)
async def finishAttack():
    ...


@ProjectRouter.post(
    "/addAttackPattern",
    response_description="Pattern successfully added",
    description="Add custom binary options as a pattern"
)
async def addAttackPattern():
    ...


@ProjectRouter.post(
    "/requestStats",
    response_description="Enjoy your stats",
    description="Request accessibility stats during specific attack"
)
async def requestStats():
    ...
