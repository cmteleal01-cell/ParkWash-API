from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "status": "ParkWash API Online",
        "version": "1.0"
    }
