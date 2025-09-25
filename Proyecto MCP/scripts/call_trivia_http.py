# propósito: probar trivia_random / trivia_check por HTTP con FastMCP 2.x
import os, json
import asyncio
from fastmcp import Client

STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "host", "last_trivia.json")

async def main():
    base = os.environ.get("TRIVIA_URL", "http://127.0.0.1:8010/mcp")  # sin '/' final evita 307
    client = Client(base)  # el transporte HTTP se infiere por la URL

    async with client:
        # 1) ping
        await client.ping()

        # 2) listar tools (devuelve una LISTA)
        tools = await client.list_tools()
        print("Tools:", [t.name for t in tools])

        # 3) pedir una pregunta
        q = await client.call_tool("trivia_random", {"category": None, "difficulty": None})
        qdata = q.data
        print("Question:", qdata["prompt"])
        print("Options:", qdata["options"])

        # 4) chequear respuesta (elige índice 0 como demo)
        choice = 0
        chk = await client.call_tool("trivia_check", {
            "question_id": qdata["question_id"],
            "chosen_index": choice,
            "answer_token": qdata["answer_token"],
        })
        print("Check:", chk.data)

def save_last_question(qdict):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(qdict, f, ensure_ascii=False, indent=2)

def load_last_question():
    if not os.path.exists(STATE_PATH):
        return None
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    asyncio.run(main())
