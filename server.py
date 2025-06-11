from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from email_analyzer import analyzeEmail

app = FastAPI()

# Allow requests from any origin (for development only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailRequest(BaseModel):
    email_text: str

@app.post("/analyze")
async def analyze_email(req: EmailRequest):
    result = analyzeEmail(req.email_text)
    return result
