import os
import uvicorn

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
