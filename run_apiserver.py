"""Main entry point for RAGIN API Server"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("pipeline.apiserver:app", host="0.0.0.0", port=8000, reload=True)
