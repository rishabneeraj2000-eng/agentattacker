"""One place to create the Gemini model, with automatic fallback when a free-tier quota runs out."""
import os

from dotenv import load_dotenv

load_dotenv()


def has_llm() -> bool:
    return bool(os.getenv("GOOGLE_API_KEY"))


def gemini(tools=None, temperature=0.0):
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_google_genai.chat_models import GoogleRateLimitError

    names = [os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")]
    names += os.getenv("GEMINI_FALLBACK_MODELS", "gemini-3.5-flash-lite,gemini-flash-lite-latest").split(",")
    models = [ChatGoogleGenerativeAI(model=n.strip(), temperature=temperature) for n in names if n.strip()]
    if tools:
        models = [m.bind_tools(tools) for m in models]
    # If one model hits its quota, try the next one.
    return models[0].with_fallbacks(models[1:], exceptions_to_handle=(GoogleRateLimitError,))
