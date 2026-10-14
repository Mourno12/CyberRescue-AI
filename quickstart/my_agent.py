"""Phase 0 throwaway quickstart agent.

Verifies that the Band SDK installs cleanly, an External Agent UUID + API key
work, and a message in a web-UI room reaches this process. Run it, open the
room in app.band.ai, post `@WarRoom-Triage say hi back`, and confirm you see
a reply.

    uv add "band-sdk[langgraph]"
    export OPENAI_API_KEY=sk-...
    python quickstart/my_agent.py

Replace AGENT_ID / API_KEY below with the throwaway-agent values from the
platform — do NOT use one of the four real WarRoom agents for this test.
"""

import asyncio
import os

from thenvoi import Agent
from thenvoi.adapters import LangGraphAdapter
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver


AGENT_ID = os.getenv("QUICKSTART_AGENT_ID", "REPLACE_ME")
API_KEY = os.getenv("QUICKSTART_API_KEY", "REPLACE_ME")


async def main() -> None:
    adapter = LangGraphAdapter(
        llm=ChatOpenAI(model="gpt-4o"),
        checkpointer=InMemorySaver(),
        custom_section=(
            "You are a quickstart test agent. When mentioned, reply briefly "
            "and report which platform tools you can see."
        ),
    )
    agent = Agent.create(adapter=adapter, agent_id=AGENT_ID, api_key=API_KEY)
    print("[QUICKSTART] connecting to Band...")
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
