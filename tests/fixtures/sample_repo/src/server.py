import os
import subprocess
from fastapi import FastAPI
import boto3

app = FastAPI()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/run-task")
def run_system_task(command: str):
    # Harmless pattern representation for static indicator test
    res = subprocess.run(["echo", command], capture_output=True)
    return {"output": res.stdout.decode()}

def fetch_user_data(user_id: int):
    # Database indicator example
    query = f"SELECT id, name FROM users WHERE id = {user_id}"
    return query

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
