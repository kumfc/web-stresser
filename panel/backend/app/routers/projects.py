from fastapi import APIRouter

from app.main import g
from app.models.entity_models import Project, AttackEntity, AttackPattern, ATypes
from app.models.request_models import CreateProjectScheme, EditProjectScheme
from app.models.response_models import SimpleResponse, CreateProjectResponseScheme, GetProjectListResponseScheme, \
    GetProjectResponseScheme, ErrorResponse, AttackListResponseScheme

ProjectRouter = APIRouter()


@ProjectRouter.post(
    "/createProject",
    response_description="Project successfully created",
    description="Create new project",
)
async def createProject(data: CreateProjectScheme):
    if g.db.has_started_projects():
        return ErrorResponse(False, error='Finish previous project first!')
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
    "/finishProject",
    response_description="Project closed",
    description="Finish existing project"
)
async def finishProject(project_id: int):
    state = g.db.finish_project(project_id)
    return SimpleResponse(state)


@ProjectRouter.post(
    "/startAttack",
    response_description="New attack started",
    description="Start new attack in existing project"
)
async def startAttack():
    # TODO check if finished
    # TODO check if attack is already running
    ...


@ProjectRouter.post(
    "/finishAttack",
    response_description="Attack has been stopped",
    description="Finish an attack"
)
async def finishAttack():
    ...  # TODO gapi finish_attack


@ProjectRouter.post(
    "/addAttackPattern",
    response_description="Pattern successfully added",
    description="Add custom binary options as a pattern"
)
async def addAttackPattern(data: AttackPattern):
    data.is_default = False
    if data.attack_type not in ATypes:
        return ErrorResponse(False, error='Unknown attack type!')

    data.bin_opts += '-ip {ip} -p {port} -bl {bl}'  # ну это абстрактно потом поменяю
    ...


@ProjectRouter.post(
    "/getAttackPatterns",
    response_description="Contains list of available attack patterns",
    description="Request list of all default and custom attack patterns"
)
async def getAttackPatterns():
    p_list = g.db.get_attack_patterns()
    a_list = list()
    for p in p_list:
        a_list.append(AttackPattern(attack_type=p['attack_type'], title=p['title'], bin_opts=p['bin_opts'],
                                    is_default=p['is_default']))

    return AttackListResponseScheme(True, attack_list=a_list)


@ProjectRouter.post(
    "/requestStats",
    response_description="Enjoy your stats",
    description="Request accessibility stats during specific attack"
)
async def requestStats():
    ...  # TODO Implement stat checking
