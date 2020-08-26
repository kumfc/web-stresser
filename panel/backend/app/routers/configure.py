from fastapi import APIRouter
from app.models.response_models import SimpleResponse
from app.main import g

CFGRouter = APIRouter()


@CFGRouter.post(
    "/setGoogleAuthKey",
    response_description="Token successfully set and validated",
    description="Set auth key for Google Compute Cloud",
)
async def setGoogleAuthKey(key_file: str = 'main-api-key.json', project_name: str = 'secret-imprint-279817'):
    return SimpleResponse(g.set_apikey(key_file, project_name))

