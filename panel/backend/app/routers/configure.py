from fastapi import APIRouter
from fastapi import HTTPException
from app.models.response_models import SimpleResponse
from app.main import g

CFGRouter = APIRouter()


@CFGRouter.post(
    "/setGoogleAuthKey",
    response_description="Token successfully set and validated",
    description="Set auth key for Google Compute Cloud",
)
async def setGoogleAuthKey(key: str):
    return SimpleResponse(g.set_apikey(key))

