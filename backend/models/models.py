from pydantic import BaseModel

class URLRequest(BaseModel):
    url: str
    domain: str
    title: str

    numForms: int
    numPasswordFields: int
    numScripts: int
    numIframes: int
    hiddenElements: int

    totalAnchors: int
    externalAnchors: int
    emptyAnchors: int