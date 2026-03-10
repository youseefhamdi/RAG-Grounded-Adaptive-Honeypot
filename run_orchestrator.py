"""Main entry point for RAGIN Orchestrator"""
import logging
from pipeline.orchestrator import RAGINOrchestrator

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    orchestrator = RAGINOrchestrator()
    orchestrator.run()
