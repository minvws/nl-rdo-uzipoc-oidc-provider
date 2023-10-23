from fastapi import Request
from fastapi.responses import JSONResponse


async def general_exception_handler(_request: Request, _exception: Exception):
    return JSONResponse("Internal Server Error", status_code=500)
