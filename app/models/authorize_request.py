from pydantic import BaseModel


class AuthorizeRequest(BaseModel):
    client_id: str
    response_type: str
    scope: str
    redirect_uri: str
    state: str
    nonce: str
    code_challenge_method: str
    code_challenge: str
