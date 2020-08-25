from fastapi import APIRouter
from fastapi import HTTPException
from app.models.response_models import SimpleResponse, CreateProjectResponseScheme, GetProjectListResponseScheme, \
    GetProjectResponseScheme
from app.models.request_models import CreateProjectScheme, EditProjectScheme
from app.models.entity_models import Project, AttackEntity

from app.main import g

ProjectRouter = APIRouter()


@ProjectRouter.post(
    "/createProject",
    response_description="Project successfully created",
    description="Create new project",
)
async def createProject(data: CreateProjectScheme):
    project_id, start_date = g.db.create_project(data.title)

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
    state = g.db.edit_project(data.id, data.title)
    return SimpleResponse(state)


@ProjectRouter.post(
    "/listProjects",
    response_description="Includes project list",
    description="Request project list"
)
async def listProjects():
    projects = g.db.get_project_list()
    if len(projects) == 0:
        return SimpleResponse(False)
    else:
        res_list = list()
        for p in projects:
            res_list.append(Project(id=p['id'], title=p['title'], is_finished=bool(p['is_finished']),
                                    start_date=p['start_date'], end_date=p['end_date'] if p['end_date'] else 0))

        return GetProjectListResponseScheme(True, project_list=res_list)


@ProjectRouter.post(
    "/getProject",
    response_description="Includes project info",
    description="Request detailed project info"
)
async def getProject(project_id: int):
    p, attacks = g.db.get_project_by_id(project_id)

    attack_c_list = list()
    for a in attacks:
        attack_c_list.append(AttackEntity(id=a['id'], attack_type=a['attack_type'], target=a['target'],
                                          start_time=a['start_time'], binary_options=a['bin_opts'],
                                          duration=a['duration']))

    project_item = Project(id=p['id'], title=p['title'], is_finished=bool(p['is_finished']), start_date=p['start_date'],
                           end_date=p['end_date'] if p['end_date'] else 0, attack_list=attack_c_list)
    # machines = g.google_api.get_machine_list()
    return GetProjectResponseScheme(True, data=project_item)


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
